package router

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/internal/metrics"
	wserver "github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/transfer"
)

// observedManager is the server manager the metrics collector reads at scrape
// time. It is set by Configure.
var observedManager atomic.Pointer[wserver.Manager]

// dockerPing checks that the Docker daemon answers. It is a variable so tests
// can replace it.
var dockerPing = func(ctx context.Context) error {
	cli, err := environment.Docker()
	if err != nil {
		return err
	}
	_, err = cli.Ping(ctx)
	return err
}

// observeManager makes m the manager reported by /metrics and registers the
// collectors that read it.
func observeManager(m *wserver.Manager) {
	observedManager.Store(m)
	metrics.RegisterOnce(newServerCollector())
}

// requestMetrics records the count and latency of every API request, labelled
// by the route template so server UUIDs and file paths do not create series.
func requestMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		metrics.HTTPInFlight.Inc()
		defer metrics.HTTPInFlight.Dec()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		method := c.Request.Method
		metrics.HTTPRequests.WithLabelValues(method, route, strconv.Itoa(c.Writer.Status())).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
	}
}

// serverCollector exports values read from the server manager when Prometheus
// scrapes, so nothing is tracked twice.
type serverCollector struct {
	serversByState *prometheus.Desc
	websockets     *prometheus.Desc
	transfers      *prometheus.Desc
	dockerUp       *prometheus.Desc

	state       *prometheus.Desc
	cpu         *prometheus.Desc
	memory      *prometheus.Desc
	memoryLimit *prometheus.Desc
	disk        *prometheus.Desc
	rx          *prometheus.Desc
	tx          *prometheus.Desc
	uptime      *prometheus.Desc
}

var serverStates = []string{
	environment.ProcessOfflineState,
	environment.ProcessStartingState,
	environment.ProcessRunningState,
	environment.ProcessStoppingState,
}

func newServerCollector() *serverCollector {
	d := func(sub, name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(metrics.Namespace, sub, name), help, labels, nil)
	}
	return &serverCollector{
		serversByState: d("", "servers", "Servers on this node, by state.", "state"),
		websockets:     d("websocket", "connections", "Authenticated server websocket connections."),
		transfers:      d("transfers", "in_progress", "Server transfers in progress, by direction.", "direction"),
		dockerUp:       d("docker", "up", "1 if the Docker daemon answered a ping during this scrape."),

		state:       d("server", "state", "1 for the current state of the server.", "server", "state"),
		cpu:         d("server", "cpu_absolute_percent", "CPU used by the server relative to the whole host, in percent.", "server"),
		memory:      d("server", "memory_bytes", "Memory used by the server.", "server"),
		memoryLimit: d("server", "memory_limit_bytes", "Memory limit of the server container.", "server"),
		disk:        d("server", "disk_bytes", "Disk space used by the server.", "server"),
		rx:          d("server", "network_rx_bytes_total", "Bytes received by the server container since it started.", "server"),
		tx:          d("server", "network_tx_bytes_total", "Bytes sent by the server container since it started.", "server"),
		uptime:      d("server", "uptime_seconds", "Time since the server container started.", "server"),
	}
}

func (sc *serverCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{sc.serversByState, sc.websockets, sc.transfers, sc.dockerUp, sc.state, sc.cpu, sc.memory, sc.memoryLimit, sc.disk, sc.rx, sc.tx, sc.uptime} {
		ch <- d
	}
}

func (sc *serverCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	up := 0.0
	if dockerPing(ctx) == nil {
		up = 1
	}
	ch <- prometheus.MustNewConstMetric(sc.dockerUp, prometheus.GaugeValue, up)
	ch <- prometheus.MustNewConstMetric(sc.transfers, prometheus.GaugeValue, float64(transfer.Incoming().Len()), "incoming")
	ch <- prometheus.MustNewConstMetric(sc.transfers, prometheus.GaugeValue, float64(transfer.Outgoing().Len()), "outgoing")

	m := observedManager.Load()
	counts := make(map[string]int, len(serverStates))
	for _, st := range serverStates {
		counts[st] = 0
	}
	websockets := 0
	perServer := config.Get().Metrics.PerServer
	if m != nil {
		for _, s := range m.All() {
			if s.Environment == nil {
				continue
			}
			st := s.Environment.State()
			counts[st]++
			websockets += s.Websockets().Len()
			if !perServer {
				continue
			}
			id := s.ID()
			for _, known := range serverStates {
				v := 0.0
				if known == st {
					v = 1
				}
				ch <- prometheus.MustNewConstMetric(sc.state, prometheus.GaugeValue, v, id, known)
			}
			if s.Filesystem() == nil && !config.Get().System.Quotas.Enabled {
				// Not fully initialized yet; Proc needs the filesystem.
				continue
			}
			p := s.Proc()
			ch <- prometheus.MustNewConstMetric(sc.cpu, prometheus.GaugeValue, p.CpuAbsolute, id)
			ch <- prometheus.MustNewConstMetric(sc.memory, prometheus.GaugeValue, float64(p.Memory), id)
			ch <- prometheus.MustNewConstMetric(sc.memoryLimit, prometheus.GaugeValue, float64(p.MemoryLimit), id)
			ch <- prometheus.MustNewConstMetric(sc.disk, prometheus.GaugeValue, float64(p.Disk), id)
			ch <- prometheus.MustNewConstMetric(sc.rx, prometheus.CounterValue, float64(p.Network.RxBytes), id)
			ch <- prometheus.MustNewConstMetric(sc.tx, prometheus.CounterValue, float64(p.Network.TxBytes), id)
			ch <- prometheus.MustNewConstMetric(sc.uptime, prometheus.GaugeValue, float64(p.Uptime)/1000, id)
		}
	}
	for st, n := range counts {
		ch <- prometheus.MustNewConstMetric(sc.serversByState, prometheus.GaugeValue, float64(n), st)
	}
	ch <- prometheus.MustNewConstMetric(sc.websockets, prometheus.GaugeValue, float64(websockets))
}

// metricsAccess decides whether a request may read /metrics. It returns 0 when
// access is allowed, or the status code to answer with. loopbackOnly is true for
// a dedicated listener bound to a loopback address, the only place /metrics is
// served without a token or allowlist.
func metricsAccess(cfg config.MetricsConfiguration, authorization, clientIP string, loopbackOnly bool) int {
	if !cfg.Enabled {
		return http.StatusNotFound
	}
	token := strings.TrimSpace(cfg.Token)
	if token == "" && len(cfg.AllowedIPs) == 0 {
		if loopbackOnly {
			return 0
		}
		// Never expose metrics on a public listener without protection.
		return http.StatusNotFound
	}
	if len(cfg.AllowedIPs) > 0 && !ipAllowed(cfg.AllowedIPs, clientIP) {
		return http.StatusForbidden
	}
	if token != "" {
		got, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			return http.StatusUnauthorized
		}
	}
	return 0
}

// ipAllowed reports whether ip is one of the addresses or CIDR ranges.
func ipAllowed(allowed []string, ip string) bool {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			if _, n, err := net.ParseCIDR(entry); err == nil && n.Contains(addr) {
				return true
			}
			continue
		}
		if e := net.ParseIP(entry); e != nil && e.Equal(addr) {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether host only accepts connections from this machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// MetricsListenerProtected reports whether a dedicated metrics listener with
// this configuration would be protected: bound to loopback, or behind a token
// or an allowlist.
func MetricsListenerProtected(cfg config.MetricsConfiguration) bool {
	return isLoopbackHost(cfg.Host) || strings.TrimSpace(cfg.Token) != "" || len(cfg.AllowedIPs) > 0
}

var metricsHandler = promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{})

// getMetrics serves /metrics on the main API listener. It is only served there
// when no dedicated metrics port is configured.
func getMetrics(c *gin.Context) {
	cfg := config.Get().Metrics
	if cfg.Port != 0 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if status := metricsAccess(cfg, c.GetHeader("Authorization"), c.ClientIP(), false); status != 0 {
		c.AbortWithStatus(status)
		return
	}
	metricsHandler.ServeHTTP(c.Writer, c.Request)
}

// HealthCheck is the result of one readiness check.
type HealthCheck struct {
	Status     string `json:"status"`
	Critical   bool   `json:"critical"`
	Message    string `json:"message,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

// HealthResponse is the body of /health/live and /health/ready.
type HealthResponse struct {
	Status string                 `json:"status"`
	Checks map[string]HealthCheck `json:"checks,omitempty"`
}

const (
	healthOK          = "ok"
	healthFail        = "fail"
	healthDegraded    = "degraded"
	healthUnavailable = "unavailable"
)

type readinessCheck struct {
	name     string
	critical bool
	run      func(ctx context.Context, cfg *config.Configuration) (string, error)
}

var readinessChecks = []readinessCheck{
	{"docker", true, checkDocker},
	{"data_directory", true, checkDataDirectory},
	{"disk_space", true, checkDiskSpace},
	{"sftp", true, checkSFTP},
	{"panel", false, checkPanel},
}

func checkDocker(ctx context.Context, _ *config.Configuration) (string, error) {
	if err := dockerPing(ctx); err != nil {
		return "", fmt.Errorf("docker daemon is not reachable: %w", err)
	}
	return "docker daemon is reachable", nil
}

func checkDataDirectory(_ context.Context, cfg *config.Configuration) (string, error) {
	dir := cfg.System.Data
	f, err := os.CreateTemp(dir, ".wings-health-*")
	if err != nil {
		return "", fmt.Errorf("data directory is not writable: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return "data directory is writable", nil
}

func checkDiskSpace(_ context.Context, cfg *config.Configuration) (string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(cfg.System.Data, &st); err != nil {
		return "", fmt.Errorf("could not read free disk space: %w", err)
	}
	free := uint64(st.Bavail) * uint64(st.Bsize) //nolint:gosec,unconvert // field types differ by platform
	minFree := uint64(max(cfg.Health.MinFreeDiskMb, 0)) << 20
	msg := fmt.Sprintf("%d MiB free, %d MiB required", free>>20, minFree>>20)
	if free < minFree {
		return "", fmt.Errorf("low disk space: %s", msg)
	}
	return msg, nil
}

func checkSFTP(_ context.Context, _ *config.Configuration) (string, error) {
	if !metrics.SFTPListening() {
		return "", fmt.Errorf("sftp server is not accepting connections")
	}
	return "sftp server is accepting connections", nil
}

// panelProbe caches the result of actively probing the Panel, so frequent
// readiness checks do not send a request to the Panel every time.
var panelProbe struct {
	mu  sync.Mutex
	at  time.Time
	err error
}

const panelProbeCache = 30 * time.Second

// probePanel sends a request to the Panel. Any HTTP response means it is
// reachable. It is a variable so tests can replace it.
var probePanel = func(ctx context.Context, cfg *config.Configuration) error {
	if cfg.PanelLocation == "" {
		return fmt.Errorf("no panel location is configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.PanelLocation, nil)
	if err != nil {
		return err
	}
	c := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Api.IgnoreCertificateErrors}, //nolint:gosec // operator setting
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	return nil
}

func checkPanel(ctx context.Context, cfg *config.Configuration) (string, error) {
	maxAge := time.Duration(max(cfg.Health.PanelContactMaxAge, 1)) * time.Second
	if last := metrics.PanelLastContact(); !last.IsZero() && time.Since(last) < maxAge {
		return fmt.Sprintf("last panel response %s ago", time.Since(last).Round(time.Second)), nil
	}
	panelProbe.mu.Lock()
	defer panelProbe.mu.Unlock()
	if time.Since(panelProbe.at) > panelProbeCache {
		panelProbe.err = probePanel(ctx, cfg)
		panelProbe.at = time.Now()
	}
	if panelProbe.err != nil {
		return "", fmt.Errorf("panel is not reachable: %w", panelProbe.err)
	}
	return "panel is reachable", nil
}

// runReadiness runs every readiness check concurrently and reports whether the
// node is ready, which it is when every critical check passes.
func runReadiness(ctx context.Context) (HealthResponse, bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg := config.Get()

	results := make([]HealthCheck, len(readinessChecks))
	var wg sync.WaitGroup
	for i, chk := range readinessChecks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			msg, err := chk.run(ctx, cfg)
			r := HealthCheck{Status: healthOK, Critical: chk.critical, Message: msg, DurationMs: time.Since(start).Milliseconds()}
			if err != nil {
				r.Status, r.Message = healthFail, err.Error()
			}
			results[i] = r
		}()
	}
	wg.Wait()

	resp := HealthResponse{Status: healthOK, Checks: make(map[string]HealthCheck, len(results))}
	ready := true
	for i, r := range results {
		resp.Checks[readinessChecks[i].name] = r
		if r.Status != healthOK {
			if r.Critical {
				ready = false
			} else if resp.Status == healthOK {
				resp.Status = healthDegraded
			}
		}
	}
	if !ready {
		resp.Status = healthUnavailable
	}
	return resp, ready
}

// readinessCache keeps the last readiness result briefly, so the public probe
// cannot be used to run the checks in a tight loop.
var readinessCache struct {
	mu    sync.Mutex
	at    time.Time
	resp  HealthResponse
	ready bool
}

const readinessCacheTTL = 2 * time.Second

func cachedReadiness(ctx context.Context) (HealthResponse, bool) {
	readinessCache.mu.Lock()
	defer readinessCache.mu.Unlock()
	if time.Since(readinessCache.at) > readinessCacheTTL {
		readinessCache.resp, readinessCache.ready = runReadiness(ctx)
		readinessCache.at = time.Now()
	}
	// Copy the checks so callers can strip details without changing the cache.
	resp := HealthResponse{Status: readinessCache.resp.Status, Checks: make(map[string]HealthCheck, len(readinessCache.resp.Checks))}
	for k, v := range readinessCache.resp.Checks {
		resp.Checks[k] = v
	}
	return resp, readinessCache.ready
}

// stripHealthDetails removes the messages and timings of the checks, which are
// only shown to authenticated callers.
func stripHealthDetails(resp HealthResponse) HealthResponse {
	for k, v := range resp.Checks {
		resp.Checks[k] = HealthCheck{Status: v.Status, Critical: v.Critical}
	}
	return resp
}

// nodeTokenAuthorized reports whether the header carries the node token.
func nodeTokenAuthorized(authorization string) bool {
	got, ok := strings.CutPrefix(authorization, "Bearer ")
	token := config.Get().Token.Token
	return ok && got != "" && token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// healthLive answers 200 while the Wings process is able to serve requests.
func healthLive(w http.ResponseWriter, _ *http.Request) {
	writeHealth(w, http.StatusOK, HealthResponse{Status: healthOK})
}

// healthReady answers 200 when every critical check passes and 503 otherwise.
// Check messages are included when detailed is true.
func healthReady(w http.ResponseWriter, r *http.Request, detailed bool) {
	resp, ready := cachedReadiness(r.Context())
	if !detailed {
		resp = stripHealthDetails(resp)
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeHealth(w, status, resp)
}

func writeHealth(w http.ResponseWriter, status int, resp HealthResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// getHealthLive is the liveness probe on the main API listener.
// @Summary Liveness probe
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health/live [get]
func getHealthLive(c *gin.Context) {
	healthLive(c.Writer, c.Request)
}

// getHealthReady is the readiness probe on the main API listener. Messages are
// shown to requests with the node token or access to /metrics.
// @Summary Readiness probe
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 503 {object} HealthResponse
// @Router /health/ready [get]
func getHealthReady(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	detailed := nodeTokenAuthorized(auth) || metricsAccess(config.Get().Metrics, auth, c.ClientIP(), false) == 0
	healthReady(c.Writer, c.Request, detailed)
}

// MetricsHandler returns the handler for the dedicated metrics listener. It
// serves /metrics, /health/live and /health/ready.
func MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	clientIP := func(r *http.Request) string {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Get().Metrics
		if status := metricsAccess(cfg, r.Header.Get("Authorization"), clientIP(r), isLoopbackHost(cfg.Host)); status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
		metricsHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /health/live", healthLive)
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Get().Metrics
		auth := r.Header.Get("Authorization")
		detailed := nodeTokenAuthorized(auth) || metricsAccess(cfg, auth, clientIP(r), isLoopbackHost(cfg.Host)) == 0
		healthReady(w, r, detailed)
	})
	return mux
}
