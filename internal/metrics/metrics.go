// Package metrics holds the Prometheus registry and the process wide metrics
// Wings records. It only depends on the Prometheus client so any package can
// record a metric without creating an import cycle. Metrics that are read from
// the server manager at scrape time are registered by the router package.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Namespace is the prefix of every metric Wings exports.
const Namespace = "featherwings"

var (
	registry = prometheus.NewRegistry()

	// HTTPRequests counts API requests by method, route template and status.
	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: "http",
		Name:      "requests_total",
		Help:      "HTTP API requests handled, by method, route and status code.",
	}, []string{"method", "route", "status"})

	// HTTPRequestDuration observes API request latency by method and route.
	HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Subsystem: "http",
		Name:      "request_duration_seconds",
		Help:      "HTTP API request latency, by method and route.",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
	}, []string{"method", "route"})

	// HTTPInFlight is the number of API requests currently being handled.
	HTTPInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "http",
		Name:      "requests_in_flight",
		Help:      "HTTP API requests currently being handled.",
	})

	// BackupsInProgress is the number of server backups being generated.
	BackupsInProgress = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "backups",
		Name:      "in_progress",
		Help:      "Server backups currently being generated.",
	})

	// BackupsTotal counts finished server backups by result (success, failure).
	BackupsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: "backups",
		Name:      "total",
		Help:      "Finished server backups, by result.",
	}, []string{"result"})

	// TransfersTotal counts finished transfers by direction (incoming,
	// outgoing) and result (success, failure).
	TransfersTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: "transfers",
		Name:      "total",
		Help:      "Finished server transfers, by direction and result.",
	}, []string{"direction", "result"})

	// SFTPSessions is the number of authenticated SFTP connections.
	SFTPSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "sftp",
		Name:      "sessions",
		Help:      "Authenticated SFTP connections currently open.",
	})

	// PanelRequests counts requests to the Panel API by result (success,
	// client_error, server_error, network_error).
	PanelRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: "panel",
		Name:      "requests_total",
		Help:      "Requests made to the Panel API, by result.",
	}, []string{"result"})

	panelLastContact = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "panel",
		Name:      "last_contact_timestamp_seconds",
		Help:      "Unix time of the last request the Panel API answered, 0 if none yet.",
	}, func() float64 {
		if t := PanelLastContact(); !t.IsZero() {
			return float64(t.UnixNano()) / 1e9
		}
		return 0
	})

	sftpListening = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "sftp",
		Name:      "listening",
		Help:      "1 if the SFTP server is accepting connections.",
	}, func() float64 {
		if SFTPListening() {
			return 1
		}
		return 0
	})

	lastPanelContact atomic.Int64
	sftpUp           atomic.Bool
	registerOnce     sync.Once
)

func init() {
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		HTTPRequests, HTTPRequestDuration, HTTPInFlight,
		BackupsInProgress, BackupsTotal, TransfersTotal,
		SFTPSessions, sftpListening,
		PanelRequests, panelLastContact,
	)
	// Make the labelled series visible at zero before the first event.
	for _, r := range []string{"success", "failure"} {
		BackupsTotal.WithLabelValues(r)
		for _, d := range []string{"incoming", "outgoing"} {
			TransfersTotal.WithLabelValues(d, r)
		}
	}
}

// Registry returns the registry every Wings metric is registered with.
func Registry() *prometheus.Registry {
	return registry
}

// RegisterOnce registers collectors with the registry the first time it is
// called. Later calls do nothing, so tests can configure routers repeatedly.
func RegisterOnce(cs ...prometheus.Collector) {
	registerOnce.Do(func() {
		for _, c := range cs {
			registry.MustRegister(c)
		}
	})
}

// RecordPanelResponse records the result of a request made to the Panel API.
// Any HTTP response, including an error status, means the Panel was reached.
func RecordPanelResponse(status int, err error) {
	switch {
	case err != nil:
		PanelRequests.WithLabelValues("network_error").Inc()
		return
	case status >= 500:
		PanelRequests.WithLabelValues("server_error").Inc()
	case status >= 400:
		PanelRequests.WithLabelValues("client_error").Inc()
	default:
		PanelRequests.WithLabelValues("success").Inc()
	}
	if status < 500 {
		lastPanelContact.Store(time.Now().UnixNano())
	}
}

// PanelLastContact returns when the Panel API last answered a request without a
// server error, or the zero time if it has not yet.
func PanelLastContact() time.Time {
	if n := lastPanelContact.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// SetSFTPListening records whether the SFTP server is accepting connections.
func SetSFTPListening(v bool) {
	sftpUp.Store(v)
}

// SFTPListening reports whether the SFTP server is accepting connections.
func SFTPListening() bool {
	return sftpUp.Load()
}
