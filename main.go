package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	authTimeout = 10 * time.Second
	dialTimeout = 5 * time.Second
	protocol    = "parallel-tunnel/1"
	maxCarriers = 320
	maxStreams  = 128
)

type settings struct {
	tunnelAddr, localAddr, tokenFile   string
	certFile, keyFile, caFile, tlsName string
	carriers, streams                  int
	pingInterval, pingTimeout          time.Duration
	token                              [32]byte
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "panel" {
		return runPanel(ctx, args[1:])
	}
	if len(args) == 0 || (args[0] != "server" && args[0] != "agent") {
		return errors.New("usage: parallel-tunnel {server|agent} -help")
	}
	server := args[0] == "server"
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var s settings
	flags.StringVar(&s.tunnelAddr, "tunnel", "", "carrier TCP address (listen on server, dial on agent)")
	flags.StringVar(&s.tokenFile, "token-file", "", "file containing the shared 64-character hex token")
	flags.DurationVar(&s.pingInterval, "ping-interval", 20*time.Second, "interval between carrier liveness probes")
	flags.DurationVar(&s.pingTimeout, "ping-timeout", 30*time.Second, "carrier ping and write timeout")
	flags.IntVar(&s.streams, "streams", 32, "maximum simultaneous streams per carrier")
	if server {
		flags.StringVar(&s.localAddr, "listen", "127.0.0.1:1081", "forwarded TCP listener")
		flags.StringVar(&s.certFile, "cert", "", "server PEM certificate")
		flags.StringVar(&s.keyFile, "key", "", "server PEM private key")
		flags.IntVar(&s.carriers, "carriers", 16, "maximum authenticated carriers")
	} else {
		flags.StringVar(&s.localAddr, "target", "", "fixed TCP backend address")
		flags.StringVar(&s.caFile, "ca", "", "trusted server certificate or CA PEM file")
		flags.StringVar(&s.tlsName, "tls-name", "", "optional server name for TLS certificate verification")
		flags.IntVar(&s.carriers, "carriers", 8, "number of independent TCP connections")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || s.carriers < 1 || s.carriers > maxCarriers || s.streams < 1 || s.streams > maxStreams ||
		s.pingInterval < time.Second || s.pingTimeout < time.Second {
		return fmt.Errorf("expected carriers 1–%d, streams 1–%d, and ping durations of at least 1s", maxCarriers, maxStreams)
	}
	host, _, err := net.SplitHostPort(s.tunnelAddr)
	if err != nil {
		return fmt.Errorf("-tunnel: %w", err)
	}
	if _, _, err := net.SplitHostPort(s.localAddr); err != nil {
		return fmt.Errorf("-listen or -target: %w", err)
	}
	token, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return fmt.Errorf("read token file: %w", err)
	}
	token = bytes.TrimSpace(token)
	if len(token) != hex.EncodedLen(len(s.token)) {
		return errors.New("token must contain 64 hex characters")
	}
	if _, err := hex.Decode(s.token[:], token); err != nil {
		return fmt.Errorf("decode token: %w", err)
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{protocol}}
	if server {
		cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
		if err != nil {
			return err
		}
		cfg.Certificates = []tls.Certificate{cert}
		return serve(ctx, s, cfg)
	}
	ca, err := os.ReadFile(s.caFile)
	if err != nil {
		return fmt.Errorf("read trust file: %w", err)
	}
	cfg.RootCAs = x509.NewCertPool()
	if !cfg.RootCAs.AppendCertsFromPEM(ca) {
		return errors.New("trust file contains no PEM certificate")
	}
	cfg.ServerName = s.tlsName
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return runAgent(ctx, s, cfg)
}

func (s settings) muxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = s.streams
	cfg.KeepAliveInterval = s.pingInterval
	cfg.ConnectionWriteTimeout = s.pingTimeout
	cfg.StreamOpenTimeout = s.pingTimeout
	cfg.MaxStreamWindowSize = 1024 * 1024
	return cfg
}

func authenticate(ctx context.Context, conn *tls.Conn, token [32]byte, admit func() bool) error {
	if err := conn.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		return err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	if conn.ConnectionState().NegotiatedProtocol != protocol {
		return errors.New("tunnel protocol mismatch")
	}
	if admit != nil {
		var received [32]byte
		if _, err := io.ReadFull(conn, received[:]); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(token[:], received[:]) != 1 {
			return errors.New("authentication rejected")
		}
		if !admit() {
			return errors.New("carrier limit reached")
		}
		if _, err := conn.Write([]byte{1}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write(token[:]); err != nil {
			return err
		}
		var reply [1]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		if reply[0] != 1 {
			return errors.New("authentication acknowledgement invalid")
		}
	}
	return conn.SetDeadline(time.Time{})
}

type carrier struct {
	session *yamux.Session
	active  int
}

type pool struct {
	mu       sync.Mutex
	carriers []*carrier
	changed  chan struct{}
	next     int
}

func newPool() *pool { return &pool{changed: make(chan struct{})} }

func (p *pool) signal() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *pool) add(c *carrier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.carriers = append(p.carriers, c)
	p.signal()
}

func (p *pool) remove(c *carrier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, current := range p.carriers {
		if c == current {
			last := len(p.carriers) - 1
			p.carriers[i] = p.carriers[last]
			p.carriers[last] = nil
			p.carriers = p.carriers[:last]
			p.signal()
			return
		}
	}
}

func (p *pool) acquire(limit int, skip map[*carrier]bool) (*carrier, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var choice *carrier
	var chosenIndex int
	for i := range p.carriers {
		index := (p.next + i) % len(p.carriers)
		c := p.carriers[index]
		if skip[c] || c.active >= limit || c.session.IsClosed() {
			continue
		}
		if choice == nil || c.active < choice.active {
			choice = c
			chosenIndex = index
		}
	}
	if choice != nil {
		choice.active++
		p.next = (chosenIndex + 1) % len(p.carriers)
	}
	return choice, p.changed
}

func (p *pool) release(c *carrier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c.active--
	p.signal()
}

func serve(ctx context.Context, s settings, cfg *tls.Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tunnel, err := net.Listen("tcp", s.tunnelAddr)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	forward, err := net.Listen("tcp", s.localAddr)
	if err != nil {
		return err
	}
	defer forward.Close()
	stop := context.AfterFunc(ctx, func() { tunnel.Close(); forward.Close() })
	defer stop()
	event(ctx, "carrier listener %s, forwarded TCP listener %s", tunnel.Addr(), forward.Addr())

	p := newPool()
	slots := make(chan struct{}, s.carriers)
	handshakes := make(chan struct{}, 32)
	errs := make(chan error, 2)
	go func() {
		errs <- accept(tunnel, handshakes, func(raw net.Conn, done func()) {
			defer done()
			reserved := false
			defer func() {
				if reserved {
					<-slots
				}
			}()
			conn := tls.Server(raw, cfg)
			stop := context.AfterFunc(ctx, func() { raw.Close() })
			defer stop()
			err := authenticate(ctx, conn, s.token, func() bool {
				select {
				case slots <- struct{}{}:
					reserved = true
					return true
				default:
					return false
				}
			})
			// Release the handshake limit once the connection has authenticated.
			done()
			if err != nil {
				event(ctx, "carrier handshake from %s: %v", raw.RemoteAddr(), err)
				return
			}
			session, err := yamux.Client(conn, s.muxConfig())
			if err != nil {
				log.Print(err)
				return
			}
			defer session.Close()
			c := &carrier{session: session}
			p.add(c)
			defer p.remove(c)
			peer := raw.RemoteAddr()
			carrierDelta(ctx, 1)
			defer carrierDelta(ctx, -1)
			event(ctx, "carrier up: %s", peer)
			<-session.CloseChan()
			event(ctx, "carrier down: %s", peer)
		})
	}()
	go func() {
		errs <- accept(forward, make(chan struct{}, s.carriers*s.streams+128), func(conn net.Conn, _ func()) {
			forwardStream(ctx, conn, p, s.streams)
		})
	}()
	err = <-errs
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func accept(listener net.Listener, slots chan struct{}, handle func(net.Conn, func())) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer conn.Close()
				done := sync.OnceFunc(func() { <-slots })
				defer done()
				handle(conn, done)
			}()
		default:
			conn.Close()
		}
	}
}

func forwardStream(ctx context.Context, conn net.Conn, p *pool, limit int) {
	tried := make(map[*carrier]bool)
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for ctx.Err() == nil {
		c, changed := p.acquire(limit, tried)
		if c == nil {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				return
			case <-changed:
				clear(tried)
				continue
			}
		}
		stream, err := c.session.OpenStream()
		if err == nil {
			defer p.release(c)
			relay(ctx, conn.(*net.TCPConn), stream)
			return
		}
		p.release(c)
		tried[c] = true
		event(ctx, "carrier stream open failed: %v", err)
	}
}

func runAgent(ctx context.Context, s settings, cfg *tls.Config) error {
	var workers sync.WaitGroup
	for i := 1; i <= s.carriers; i++ {
		workers.Go(func() {
			backoff := time.Second
			for ctx.Err() == nil {
				start := time.Now()
				err := agentCarrier(ctx, s, cfg, i)
				if ctx.Err() != nil {
					return
				}
				event(ctx, "carrier %d down: %v", i, err)
				if time.Since(start) >= time.Minute {
					backoff = time.Second
				}
				timer := time.NewTimer(backoff + rand.N(backoff/2))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				backoff = min(2*backoff, 30*time.Second)
			}
		})
	}
	workers.Wait()
	return nil
}

func agentCarrier(ctx context.Context, s settings, cfg *tls.Config, id int) error {
	dialer := net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", s.tunnelAddr)
	if err != nil {
		return err
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	conn := tls.Client(raw, cfg)
	if err := authenticate(ctx, conn, s.token, nil); err != nil {
		return err
	}
	session, err := yamux.Server(conn, s.muxConfig())
	if err != nil {
		return err
	}
	defer session.Close()
	carrierDelta(ctx, 1)
	defer carrierDelta(ctx, -1)
	event(ctx, "carrier %d up: %s", id, raw.RemoteAddr())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, s.streams)
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				target, err := dialer.DialContext(ctx, "tcp", s.localAddr)
				if err != nil {
					event(ctx, "backend dial failed: %v", err)
					stream.Close()
					return
				}
				relay(ctx, target.(*net.TCPConn), stream)
			}()
		default:
			stream.Close()
		}
	}
}

func relay(ctx context.Context, tcp *net.TCPConn, stream *yamux.Stream) {
	defer tcp.Close()
	m := statsFrom(ctx)
	if m != nil {
		m.active.Add(1)
		defer m.active.Add(-1)
	}
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() {
		now := time.Now()
		tcp.SetDeadline(now)
		stream.SetDeadline(now)
	})
	defer stop()
	results := make(chan error, 2)
	go func() {
		_, err := copyMeasured(stream, tcp, m, true)
		if err == nil {
			err = stream.Close() // Yamux sends FIN and leaves the read side open.
		}
		results <- err
	}()
	go func() {
		_, err := copyMeasured(tcp, stream, m, false)
		if err == nil {
			err = tcp.CloseWrite()
		}
		results <- err
	}()
	if err := <-results; err != nil {
		now := time.Now()
		tcp.SetDeadline(now)
		stream.SetDeadline(now)
	}
	<-results
}
