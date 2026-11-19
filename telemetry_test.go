package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/hashicorp/yamux"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestObservedWriteStallAndErrorClassification(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	m := newTelemetry("test")
	c := observeConn(left, m)
	m.register(c)
	defer m.unregister(c)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.Write([]byte("hello")) }()
	until := time.Now().Add(time.Second)
	for c.writingSince.Load() == 0 {
		if time.Now().After(until) {
			t.Fatal("write not started")
		}
		time.Sleep(time.Millisecond)
	}
	sample := m.snapshot()
	if sample["writes_in_progress"] != 1 {
		t.Fatal("blocked write not visible", sample)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(right, got); err != nil {
		t.Fatal(err)
	}
	<-done
	if c.writeBytes.Load() != 5 || c.writingSince.Load() != 0 || c.maxWriteNS.Load() <= 0 {
		t.Fatal("write metrics wrong")
	}
	var logs bytes.Buffer
	l := diagnosticLogger{log.New(&logs, "", 0), c}
	l.Printf("[ERR] yamux: aborted stream open (destination=%s): i/o deadline reached", "test")
	l.Printf("[ERR] yamux: Failed to read stream data: closed")
	if reason := c.firstError.Load(); reason == nil || *reason != "stream_ack_timeout" {
		t.Fatal("original error masked")
	}
	if !strings.Contains(logs.String(), "aborted stream open") {
		t.Fatal("original logs lost")
	}
}
func TestTelemetryQueueCancellationAndRejection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := newTelemetry("server")
	ctx = context.WithValue(ctx, telemetryKey{}, m)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan struct{})
	go func() { forwardStream(ctx, left, newPool(), 1); close(done) }()
	until := time.Now().Add(time.Second)
	for m.waiting.Load() != 1 {
		if time.Now().After(until) {
			t.Fatal("wait not counted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation hung")
	}
	if m.waiting.Load() != 0 || m.queueWaits.Load() != 1 || m.queueTimeouts.Load() != 0 {
		t.Fatal("queue counters wrong")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		acceptObserved(listener, make(chan struct{}), m, func(net.Conn, func()) { t.Error("over limit connection accepted") })
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("over limit client left open")
	}
	listener.Close()
	<-accepted
	if m.rejected.Load() != 1 || m.accepted.Load() != 1 {
		t.Fatal("admission counters wrong")
	}
}
func TestTelemetrySurvivesConcurrentSamples(t *testing.T) {
	m := newTelemetry("server")
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := observeConn(left, m)
	m.register(c)
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); io.Copy(io.Discard, right) }()
	for i := 0; i < 100; i++ {
		if _, err := c.Write([]byte("test")); err != nil {
			t.Fatal(err)
		}
		m.snapshot()
	}
	left.Close()
	group.Wait()
	m.unregister(c)
	if m.carrierUp.Load() != 1 || m.carrierDown.Load() != 1 {
		t.Fatal("carrier totals wrong")
	}
}
func TestAckTimeoutDiagnosticsPreserveExistingSemantics(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	m := newTelemetry("server")
	conn := observeConn(left, m)
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = false
	config.StreamOpenTimeout = 40 * time.Millisecond
	config.ConnectionWriteTimeout = time.Second
	config.LogOutput = nil
	config.Logger = diagnosticLogger{log.New(io.Discard, "", 0), conn}
	client, err := yamux.Client(conn, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peerCfg := yamux.DefaultConfig()
	peerCfg.EnableKeepAlive = false
	peer, err := yamux.Server(right, peerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	// A live peer that does not AcceptStream never acknowledges the SYN.
	if _, err := client.OpenStream(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.CloseChan():
	case <-time.After(2 * time.Second):
		t.Fatal("ACK timeout did not fire")
	}
	if reason := conn.firstError.Load(); reason == nil || *reason != "stream_ack_timeout" {
		t.Fatal("ACK timeout cause not captured")
	}
}
func TestStatsIntervalValidation(t *testing.T) {
	for _, value := range []string{"-1s", "1s", "4s"} {
		if err := run(context.Background(), []string{"server", "-stats-interval", value}); err == nil || !strings.Contains(err.Error(), "stats-interval") {
			t.Fatalf("accepted interval %s: %v", value, err)
		}
	}
}

func TestStallAwareSelectionAndFallback(t *testing.T) {
	makeCarrier := func(active int) *carrier {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		cfg := yamux.DefaultConfig()
		cfg.EnableKeepAlive = false
		client, e := yamux.Client(a, cfg)
		if e != nil {
			t.Fatal(e)
		}
		peer, e := yamux.Server(b, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { client.Close(); peer.Close() })
		return &carrier{session: client, active: active, observed: observeConn(a, newTelemetry("server"))}
	}
	p := newPool()
	slow, healthy := makeCarrier(0), makeCarrier(1)
	slow.observed.writingSince.Store(time.Now().Add(-2 * time.Second).UnixNano())
	p.add(slow)
	p.add(healthy)
	picked, _ := p.acquireAvoidingStalls(4, nil, time.Second)
	if picked != healthy {
		t.Fatal("new stream assigned to stalled carrier despite healthy alternative")
	}
	p.release(picked)
	if healthy.observed.owner.stallAvoided.Load() != 1 {
		t.Fatal("avoidance counter missing")
	}
	picked, _ = p.acquire(4, nil)
	if picked != slow {
		t.Fatal("default balancing changed")
	}
	p.release(picked)
	healthy.observed.writingSince.Store(time.Now().Add(-2 * time.Second).UnixNano())
	picked, _ = p.acquireAvoidingStalls(4, nil, time.Second)
	if picked != slow {
		t.Fatal("all-stalled fallback did not preserve least-stream selection")
	}
	p.release(picked)
}

func TestAgentCountsRejectedAuthentication(t *testing.T) {
	serverTLS, agentTLS := testTLS(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, e := listener.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		var token [32]byte
		token[0] = 42
		_ = authenticate(ctx, tls.Server(raw, serverTLS), token, func() bool { return true })
	}()
	m := newTelemetry("agent")
	agentCtx := context.WithValue(ctx, telemetryKey{}, m)
	err = agentCarrier(agentCtx, settings{tunnelAddr: listener.Addr().String()}, agentTLS, 1)
	if err == nil || m.handshakeErrors.Load() != 1 {
		t.Fatal("rejected authentication not counted", err)
	}
	<-done
}
