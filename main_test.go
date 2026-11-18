package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestPoolWaiterWakesWhenCapacityReturns(t *testing.T) {
	p := newPool()
	// An empty pool exposes a notification that closes when a carrier arrives.
	c, changed := p.acquire(1, nil)
	if c != nil {
		t.Fatal("empty pool returned a carrier")
	}
	carrier := &carrier{}
	p.add(carrier)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("adding a carrier did not wake the waiter")
	}
}

func TestPoolSupports40960ConcurrentStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("large session pool")
	}
	p := newPool()
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = maxStreams
	cfg.EnableKeepAlive = false
	peers := make(map[*carrier]*yamux.Session, maxCarriers)
	for range maxCarriers {
		left, right := net.Pipe()
		t.Cleanup(func() { left.Close(); right.Close() })
		client, err := yamux.Client(left, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		server, err := yamux.Server(right, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		c := &carrier{session: client}
		p.add(c)
		peers[c] = server
	}
	const capacity = maxCarriers * maxStreams
	for i := range capacity {
		c, _ := p.acquire(maxStreams, nil)
		if c == nil {
			t.Fatalf("pool full at %d streams", i)
		}
		if _, err := c.session.OpenStream(); err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		if _, err := peers[c].AcceptStream(); err != nil {
			t.Fatalf("accept stream %d: %v", i, err)
		}
	}
	if c, _ := p.acquire(maxStreams, nil); c != nil {
		t.Fatal("pool exceeded configured capacity")
	}
	for c, peer := range peers {
		if c.active != maxStreams || peer.NumStreams() != maxStreams {
			t.Fatalf("carrier occupancy = %d, peer = %d", c.active, peer.NumStreams())
		}
	}
}

func TestCarrierFailureLeavesOtherStreamsAlive(t *testing.T) {
	listen := func() net.Listener {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	tunnel, forward := listen(), listen()
	tunnel.Close()
	forward.Close()
	s := settings{
		tunnelAddr: tunnel.Addr().String(), localAddr: forward.Addr().String(),
		carriers: 2, streams: 4, pingInterval: time.Second, pingTimeout: 2 * time.Second,
	}
	s.token[0] = 42
	serverTLS, agentTLS := testTLS(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- serve(ctx, s, serverTLS) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-stopped:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})

	dial := func(addr string) net.Conn {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				t.Cleanup(func() { conn.Close() })
				return conn
			}
			if time.Now().After(until) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	rejected := dial(s.tunnelAddr)
	if err := authenticate(ctx, tls.Client(rejected, agentTLS), [32]byte{}, nil); err == nil {
		t.Fatal("server accepted an invalid token")
	}
	rejected.Close()

	addAgent := func(label byte) net.Conn {
		t.Helper()
		raw := dial(s.tunnelAddr)
		conn := tls.Client(raw, agentTLS)
		if err := authenticate(ctx, conn, s.token, nil); err != nil {
			t.Fatal(err)
		}
		session, err := yamux.Server(conn, s.muxConfig())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { session.Close() })
		go func() {
			for {
				stream, err := session.AcceptStream()
				if err != nil {
					return
				}
				go func() {
					defer stream.Close()
					if _, err := stream.Write([]byte{label}); err == nil {
						_, _ = io.Copy(stream, stream)
					}
				}()
			}
		}()
		return raw
	}

	readByte := func(conn net.Conn) byte {
		t.Helper()
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			t.Fatal(err)
		}
		return b[0]
	}
	waitForward := func() (net.Conn, byte) {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for {
			conn := dial(s.localAddr)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var b [1]byte
			if _, err := io.ReadFull(conn, b[:]); err == nil {
				return conn, b[0]
			}
			conn.Close()
			if time.Now().After(until) {
				t.Fatal("forwarded listener did not get a carrier")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	firstAgent := addAgent('a')
	first, label := waitForward()
	if label != 'a' {
		t.Fatalf("first stream used carrier %q", label)
	}
	secondAgent := addAgent('b')
	// The acknowledgement precedes pool registration. Retry a bounded number of
	// times until the new, less loaded carrier receives the next stream.
	var second net.Conn
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		conn, label := waitForward()
		if label == 'b' {
			second = conn
			break
		}
		conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if second == nil {
		t.Fatal("second carrier never received a stream")
	}
	firstAgent.Close()
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream on closed carrier survived")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("stream on closed carrier hung")
	}
	if _, err := second.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	// Half-close before reading, as TCP protocols that delimit a request by EOF do.
	if err := second.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := readByte(second); got != 'x' {
		t.Fatalf("surviving stream got %q", got)
	}
	if _, err := second.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("surviving stream did not finish cleanly: %v", err)
	}
	next, label := waitForward()
	next.Close()
	if label != 'b' {
		t.Fatalf("new stream used carrier %q", label)
	}

	secondAgent.Close()
	backend := listen()
	payload := bytes.Repeat([]byte("tcp-forwarding"), 200_000)
	backendResult := make(chan error, 1)
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			backendResult <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{'c'}); err != nil {
			backendResult <- err
			return
		}
		received, err := io.ReadAll(io.LimitReader(conn, int64(len(payload)+1)))
		if err == nil && bytes.Equal(received, payload) {
			_, err = conn.Write([]byte{'y'})
		}
		backendResult <- err
	}()
	agentSettings := s
	agentSettings.carriers = 1
	agentSettings.localAddr = backend.Addr().String()
	agentStopped := make(chan struct{})
	go func() {
		defer close(agentStopped)
		_ = runAgent(ctx, agentSettings, agentTLS)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-agentStopped:
		case <-time.After(3 * time.Second):
			t.Error("agent did not stop")
		}
	})
	conn, label := waitForward()
	if label != 'c' {
		t.Fatalf("new stream after reconnect used backend %q", label)
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if readByte(conn) != 'y' {
		t.Fatal("backend did not confirm the payload")
	}
	if err := <-backendResult; err != nil {
		t.Fatal(err)
	}
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{netip.MustParseAddr("127.0.0.1").AsSlice()},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{
			MinVersion: tls.VersionTLS13, NextProtos: []string{protocol},
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		}, &tls.Config{
			MinVersion: tls.VersionTLS13, NextProtos: []string{protocol},
			ServerName: "127.0.0.1", RootCAs: roots,
		}
}
