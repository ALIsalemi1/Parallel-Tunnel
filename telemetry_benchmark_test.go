package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func BenchmarkTelemetryRelay(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			serverTLS, agentTLS := testTLS(b)
			freeAddress := func() string {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					b.Fatal(e)
				}
				a := l.Addr().String()
				l.Close()
				return a
			}
			backend, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				b.Fatal(e)
			}
			defer backend.Close()
			go func() {
				for {
					c, e := backend.Accept()
					if e != nil {
						return
					}
					go func() { defer c.Close(); io.Copy(c, c) }()
				}
			}()
			settings := settings{tunnelAddr: freeAddress(), localAddr: freeAddress(), carriers: 1, streams: 8, pingInterval: 5 * time.Second, pingTimeout: 10 * time.Second}
			settings.token[0] = 42
			root, cancel := context.WithCancel(context.Background())
			defer cancel()
			serverCtx, agentCtx := root, root
			if enabled {
				serverCtx = context.WithValue(root, telemetryKey{}, newTelemetry("server"))
				agentCtx = context.WithValue(root, telemetryKey{}, newTelemetry("agent"))
			}
			serverDone := make(chan error, 1)
			go func() { serverDone <- serve(serverCtx, settings, serverTLS) }()
			agentDone := make(chan struct{})
			agentSettings := settings
			agentSettings.localAddr = backend.Addr().String()
			go func() { defer close(agentDone); runAgent(agentCtx, agentSettings, agentTLS) }()
			var conn net.Conn
			until := time.Now().Add(4 * time.Second)
			for {
				conn, e = net.DialTimeout("tcp", settings.localAddr, time.Second)
				if e == nil {
					break
				}
				if time.Now().After(until) {
					b.Fatal(e)
				}
				time.Sleep(time.Millisecond)
			}
			defer func() { conn.Close(); cancel(); <-agentDone; <-serverDone }()
			conn.SetDeadline(time.Now().Add(2 * time.Minute))
			conn.Write([]byte{1})
			if _, e = io.ReadFull(conn, make([]byte, 1)); e != nil {
				b.Fatal(e)
			}
			payload := bytes.Repeat([]byte("x"), 32<<10)
			received := make([]byte, len(payload))
			b.SetBytes(int64(2 * len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, e = conn.Write(payload); e != nil {
					b.Fatal(e)
				}
				if _, e = io.ReadFull(conn, received); e != nil {
					b.Fatal(e)
				}
			}
			b.StopTimer()
		})
	}
}
