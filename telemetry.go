package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type telemetryKey struct{}
type telemetry struct {
	role                                                                                      string
	started                                                                                   time.Time
	stallAvoided                                                                              atomic.Uint64
	sequence                                                                                  atomic.Uint64
	accepted, rejected, queueWaits, queueTimeouts, openErrors, backendErrors, handshakeErrors atomic.Uint64
	relayErrors, carrierUp, carrierDown                                                       atomic.Uint64
	activeRelays, waiting                                                                     atomic.Int64
	maxQueueNS, maxOpenNS, maxBackendNS                                                       atomic.Int64
	mu                                                                                        sync.Mutex
	carriers                                                                                  map[*observedConn]struct{}
	cpuTotal, cpuSteal                                                                        uint64
}

func telemetryFrom(ctx context.Context) *telemetry {
	m, _ := ctx.Value(telemetryKey{}).(*telemetry)
	return m
}
func newTelemetry(role string) *telemetry {
	return &telemetry{role: role, started: time.Now(), carriers: make(map[*observedConn]struct{})}
}
func observeMax(dst *atomic.Int64, value int64) {
	for {
		old := dst.Load()
		if value <= old || dst.CompareAndSwap(old, value) {
			return
		}
	}
}
func (m *telemetry) register(c *observedConn) {
	m.mu.Lock()
	m.carriers[c] = struct{}{}
	m.mu.Unlock()
	m.carrierUp.Add(1)
}
func (m *telemetry) unregister(c *observedConn) {
	m.mu.Lock()
	delete(m.carriers, c)
	m.mu.Unlock()
	m.carrierDown.Add(1)
}
func (m *telemetry) report(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.emit("final")
			return
		case <-ticker.C:
			m.emit("periodic")
		}
	}
}
func cpuStealTicks() (uint64, uint64, bool) {
	b, e := os.ReadFile("/proc/stat")
	if e != nil {
		return 0, 0, false
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fields := strings.Fields(line)
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0, 0, false
	}
	var total, steal uint64
	// guest and guest_nice are already included in user/nice: count only the first eight fields.
	for i := 1; i <= 8; i++ {
		v, e := strconv.ParseUint(fields[i], 10, 64)
		if e != nil {
			return 0, 0, false
		}
		total += v
		if i == 8 {
			steal = v
		}
	}
	return total, steal, true
}
func (m *telemetry) snapshot() map[string]any {
	var carrierBytesIn, carrierBytesOut uint64
	var longestWrite int64
	var busiestID uint64
	var pendingWrites int
	var maxPendingMS int64
	m.mu.Lock()
	count := len(m.carriers)
	for c := range m.carriers {
		carrierBytesIn += c.readBytes.Load()
		carrierBytesOut += c.writeBytes.Load()
		w := c.maxWriteNS.Load()
		if w > longestWrite {
			longestWrite = w
			busiestID = c.id
		}
		if started := c.writingSince.Load(); started != 0 {
			pendingWrites++
			elapsed := time.Now().UnixNano() - started
			if elapsed > maxPendingMS {
				maxPendingMS = elapsed
			}
		}
	}
	m.mu.Unlock()
	samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/sched/goroutines:goroutines"}}
	metrics.Read(samples)
	result := map[string]any{
		"role":                      m.role,
		"uptime_s":                  int64(time.Since(m.started).Seconds()),
		"carriers":                  count,
		"carrier_up_total":          m.carrierUp.Load(),
		"carrier_down_total":        m.carrierDown.Load(),
		"relays":                    m.activeRelays.Load(),
		"waiting":                   m.waiting.Load(),
		"accepted_total":            m.accepted.Load(),
		"capacity_reject_total":     m.rejected.Load(),
		"stall_avoidance_total":     m.stallAvoided.Load(),
		"queue_wait_total":          m.queueWaits.Load(),
		"queue_timeout_total":       m.queueTimeouts.Load(),
		"open_error_total":          m.openErrors.Load(),
		"backend_error_total":       m.backendErrors.Load(),
		"handshake_error_total":     m.handshakeErrors.Load(),
		"relay_error_total":         m.relayErrors.Load(),
		"max_queue_ms":              float64(m.maxQueueNS.Load()) / 1e6,
		"max_open_call_ms":          float64(m.maxOpenNS.Load()) / 1e6,
		"max_backend_dial_ms":       float64(m.maxBackendNS.Load()) / 1e6,
		"connected_mux_read_bytes":  carrierBytesIn,
		"connected_mux_write_bytes": carrierBytesOut,
		"max_carrier_write_ms":      float64(longestWrite) / 1e6,
		"max_write_carrier_id":      busiestID,
		"writes_in_progress":        pendingWrites,
		"max_pending_write_ms":      float64(maxPendingMS) / 1e6,
		"heap_bytes":                samples[0].Value.Uint64(),
		"goroutines":                samples[1].Value.Uint64(),
	}
	if total, steal, ok := cpuStealTicks(); ok {
		if m.cpuTotal != 0 && total > m.cpuTotal && steal >= m.cpuSteal {
			result["host_cpu_steal_pct"] = 100 * float64(steal-m.cpuSteal) / float64(total-m.cpuTotal)
		}
		m.cpuTotal = total
		m.cpuSteal = steal
	}
	return result
}
func (m *telemetry) emit(kind string) {
	result := m.snapshot()
	result["sample"] = kind
	b, _ := json.Marshal(result)
	log.Printf("tunnel_stats %s", b)
}

type observedConn struct {
	net.Conn
	owner                                         *telemetry
	id                                            uint64
	started                                       time.Time
	readBytes, writeBytes                         atomic.Uint64
	maxWriteNS, writingSince, lastRead, lastWrite atomic.Int64
	firstError                                    atomic.Pointer[string]
}

func observeConn(conn net.Conn, m *telemetry) *observedConn {
	return &observedConn{Conn: conn, owner: m, id: m.sequence.Add(1), started: time.Now()}
}
func (c *observedConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.readBytes.Add(uint64(n))
		c.lastRead.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *observedConn) Write(b []byte) (int, error) {
	start := time.Now()
	c.writingSince.Store(start.UnixNano())
	n, e := c.Conn.Write(b)
	elapsed := time.Since(start)
	observeMax(&c.maxWriteNS, elapsed.Nanoseconds())
	c.writingSince.Store(0)
	if n > 0 {
		c.writeBytes.Add(uint64(n))
		c.lastWrite.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *observedConn) record(message string) {
	reason := ""
	switch {
	case strings.Contains(message, "aborted stream open"):
		reason = "stream_ack_timeout"
	case strings.Contains(message, "keepalive failed"):
		reason = "keepalive_failure"
	case strings.Contains(message, "Failed to write"):
		reason = "transport_write_failure"
	case strings.Contains(message, "Failed to read"):
		reason = "transport_read_failure"
	case strings.Contains(message, "backlog exceeded"):
		return // A rejected stream does not itself terminate the carrier.
	}
	if reason != "" {
		c.firstError.CompareAndSwap(nil, &reason)
	}
}
func (c *observedConn) closed(ctx context.Context, streams int) {
	reason := "session_closed"
	if r := c.firstError.Load(); r != nil {
		reason = *r
	}
	if ctx.Err() != nil {
		reason = "local_shutdown"
	}
	age := func(stamp int64) any {
		if stamp == 0 {
			return nil
		}
		return float64(time.Now().UnixNano()-stamp) / 1e6
	}
	result := map[string]any{
		"role":              c.owner.role,
		"carrier_id":        c.id,
		"peer":              c.RemoteAddr().String(),
		"reason":            reason,
		"lifetime_s":        int64(time.Since(c.started).Seconds()),
		"streams_at_close":  streams,
		"mux_read_bytes":    c.readBytes.Load(),
		"mux_write_bytes":   c.writeBytes.Load(),
		"max_write_ms":      float64(c.maxWriteNS.Load()) / 1e6,
		"last_read_age_ms":  age(c.lastRead.Load()),
		"last_write_age_ms": age(c.lastWrite.Load()),
	}
	b, _ := json.Marshal(result)
	log.Printf("carrier_diagnostics %s", b)
}

type diagnosticLogger struct {
	*log.Logger
	c *observedConn
}

func (l diagnosticLogger) Printf(format string, v ...interface{}) {
	l.c.record(fmt.Sprintf(format, v...))
	l.Logger.Printf(format, v...)
}
func (l diagnosticLogger) Print(v ...interface{}) { l.c.record(fmt.Sprint(v...)); l.Logger.Print(v...) }
func (l diagnosticLogger) Println(v ...interface{}) {
	l.c.record(fmt.Sprintln(v...))
	l.Logger.Println(v...)
}
