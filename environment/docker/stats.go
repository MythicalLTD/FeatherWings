package docker

import (
	"context"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
	"github.com/docker/docker/api/types/container"
	"github.com/goccy/go-json"

	"github.com/mythicalltd/featherwings/environment"
)

// Uptime returns the current uptime of the container in milliseconds. If the
// container is not currently running this will return 0.
func (e *Environment) Uptime(ctx context.Context) (int64, error) {
	ins, err := e.ContainerInspect(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "environment: could not inspect container")
	}
	if !ins.State.Running {
		return 0, nil
	}
	started, err := time.Parse(time.RFC3339, ins.State.StartedAt)
	if err != nil {
		return 0, errors.Wrap(err, "environment: failed to parse container start time")
	}
	return time.Since(started).Milliseconds(), nil
}

// pollResources attaches to the Docker stats stream and emits resource events
// whenever usage changes. While the container remains active, the stats stream
// is automatically re-opened if Docker closes it (common after a Wings daemon
// restart re-attaches to an already-running container). Without that retry the
// console attach can stay healthy while CPU/memory stay stuck at 0.
func (e *Environment) pollResources(ctx context.Context) error {
	// Offline/error during attach races is expected; treat as a no-op so callers
	// do not Error-log a benign condition after crash/stop transitions.
	if e.isStatsInactive() {
		return nil
	}

	e.log().Info("starting resource polling for container")
	defer e.log().Debug("stopped resource polling for container")

	// Seed uptime once; subsequent samples advance it from PreRead/Read deltas.
	// Bound the inspect so a hung Docker API cannot block stats forever.
	var uptime int64
	uctx, ucancel := context.WithTimeout(ctx, DefaultDockerOpTimeout)
	u, uerr := e.Uptime(uctx)
	ucancel()
	if uerr != nil {
		e.log().WithField("error", uerr).Warn("failed to calculate container uptime")
	} else {
		uptime = u
	}

	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.isStatsInactive() {
			return nil
		}

		err := e.streamResources(ctx, &uptime)
		// Only stop polling when the attach-owned parent context is done.
		// Stream-local cancels (stall watchdog) and EOFs should reopen.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			e.log().WithField("error", err).Debug("resource stats stream ended; retrying while container is active")
		} else {
			e.log().Debug("resource stats stream closed; retrying while container is active")
		}

		if e.isStatsInactive() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

func (e *Environment) isStatsInactive() bool {
	st := e.st.Load()
	return st == environment.ProcessOfflineState || st == environment.ProcessErrorState
}

// streamResources opens a single Docker stats stream and publishes events until
// the stream ends, the context is canceled, or the process goes offline.
func (e *Environment) streamResources(ctx context.Context, uptime *int64) error {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stats, err := e.client.ContainerStats(streamCtx, e.Id, true)
	if err != nil {
		return err
	}

	e.mu.Lock()
	if e.stats != nil {
		_ = e.stats.Close()
	}
	e.stats = stats.Body
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		if e.stats == stats.Body {
			e.stats = nil
		}
		e.mu.Unlock()
		_ = stats.Body.Close()
	}()

	e.log().Debug("resource stats stream established")

	// Docker normally emits ~1 sample/sec. If the body stalls after a Wings
	// re-attach (no frames, no EOF), cancel and let the caller reopen it.
	var lastFrame atomic.Int64
	lastFrame.Store(time.Now().UnixNano())
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-streamCtx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastFrame.Load())) > 15*time.Second {
					e.log().Warn("resource stats stream stalled; reopening")
					e.mu.Lock()
					if e.stats != nil {
						_ = e.stats.Close()
					}
					e.mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()

	dec := json.NewDecoder(stats.Body)
	for {
		select {
		case <-streamCtx.Done():
			return streamCtx.Err()
		default:
			var v container.StatsResponse
			if err := dec.Decode(&v); err != nil {
				if err != io.EOF && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					e.log().WithField("error", err).Warn("error while processing Docker stats output for container")
					return err
				}
				// EOF or cancel — caller retries while the process is still active.
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				return nil
			}
			lastFrame.Store(time.Now().UnixNano())

			// Disable collection if the server is in an offline state and this process is still running.
			if e.st.Load() == environment.ProcessOfflineState {
				e.log().Debug("process in offline state while resource polling is still active; stopping poll")
				return nil
			}

			if !v.PreRead.IsZero() {
				*uptime = *uptime + v.Read.Sub(v.PreRead).Milliseconds()
			}

			st := environment.Stats{
				Uptime:      *uptime,
				Memory:      calculateDockerMemory(v.MemoryStats),
				MemoryLimit: v.MemoryStats.Limit,
				CpuAbsolute: calculateDockerAbsoluteCpu(v.PreCPUStats, v.CPUStats),
				Network:     environment.NetworkStats{},
			}

			for _, nw := range v.Networks {
				st.Network.RxBytes += nw.RxBytes
				st.Network.TxBytes += nw.TxBytes
			}

			// Docker surfaces cgroup block I/O counters through the blkio
			// recursive list on both cgroup v1 ("Read"/"Write") and v2
			// ("read"/"write" from io.stat), so match the op case-insensitively.
			for _, bio := range v.BlkioStats.IoServiceBytesRecursive {
				if strings.EqualFold(bio.Op, "read") {
					st.DiskIo.ReadBytes += bio.Value
				} else if strings.EqualFold(bio.Op, "write") {
					st.DiskIo.WriteBytes += bio.Value
				}
			}

			e.Events().Publish(environment.ResourceEvent, st)
		}
	}
}

// The "docker stats" CLI call does not return the same value as the types.MemoryStats.Usage
// value which can be rather confusing to people trying to compare panel usage to
// their stats output.
//
// This math is from their CLI repository in order to show the same values to avoid people
// bothering me about it. It should also reflect a slightly more correct memory value anyways.
//
// @see https://github.com/docker/cli/blob/96e1d1d6/cli/command/container/stats_helpers.go#L227-L249
func calculateDockerMemory(stats container.MemoryStats) uint64 {
	if v, ok := stats.Stats["total_inactive_file"]; ok && v < stats.Usage {
		return stats.Usage - v
	}

	if v := stats.Stats["inactive_file"]; v < stats.Usage {
		return stats.Usage - v
	}

	return stats.Usage
}

// Calculates the absolute CPU usage used by the server process on the system, not constrained
// by the defined CPU limits on the container.
//
// @see https://github.com/docker/cli/blob/aa097cf1aa19099da70930460250797c8920b709/cli/command/container/stats_helpers.go#L166
func calculateDockerAbsoluteCpu(pStats container.CPUStats, stats container.CPUStats) float64 {
	// Calculate the change in CPU usage between the current and previous reading.
	cpuDelta := float64(stats.CPUUsage.TotalUsage) - float64(pStats.CPUUsage.TotalUsage)

	// Calculate the change for the entire system's CPU usage between current and previous reading.
	systemDelta := float64(stats.SystemUsage) - float64(pStats.SystemUsage)

	// Calculate the total number of CPU cores being used.
	cpus := float64(stats.OnlineCPUs)
	if cpus == 0.0 {
		cpus = float64(len(stats.CPUUsage.PercpuUsage))
	}

	percent := 0.0
	if systemDelta > 0.0 && cpuDelta > 0.0 {
		percent = (cpuDelta / systemDelta) * 100.0

		if cpus > 0 {
			percent *= cpus
		}
	}

	return math.Round(percent*1000) / 1000
}
