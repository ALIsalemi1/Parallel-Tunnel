package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPanel(t *testing.T) (*panel, *http.Cookie, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p, e := newPanel(ctx, filepath.Join(t.TempDir(), "panel.json"), "a-long-test-password-only", false)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://localhost/api/login", strings.NewReader(`{"password":"a-long-test-password-only"}`))
	p.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var d map[string]string
	json.Unmarshal(w.Body.Bytes(), &d)
	return p, w.Result().Cookies()[0], d["csrf"]
}
func requestPanel(p *panel, cookie *http.Cookie, csrf, method, path string, body any) *httptest.ResponseRecorder {
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, "http://localhost"+path, &b)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	p.handler().ServeHTTP(w, r)
	return w
}
func TestPanelAuthenticationAndCSRF(t *testing.T) {
	p, c, csrf := testPanel(t)
	if w := requestPanel(p, nil, "", "GET", "/api/status", nil); w.Code != 401 {
		t.Fatal("anonymous status", w.Code)
	}
	if w := requestPanel(p, c, "", "POST", "/api/action", map[string]string{"id": "missing", "action": "stop"}); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	r := httptest.NewRequest("POST", "http://localhost/api/logout", strings.NewReader("{}"))
	r.AddCookie(c)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	p.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross origin", w.Code)
	}
	if w = requestPanel(p, c, csrf, "POST", "/api/logout", map[string]string{}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = requestPanel(p, c, "", "GET", "/api/status", nil); w.Code != 401 {
		t.Fatal("logout left valid cookie")
	}
}
func TestPanelLoginThrottling(t *testing.T) {
	p, _, _ := testPanel(t)
	for i := 0; i < 6; i++ {
		w := requestPanel(p, nil, "", "POST", "/api/login", map[string]string{"password": "wrong"})
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d got %d", i, w.Code)
		}
	}
}
func testConfigFiles(t *testing.T) tunnelConfig {
	t.Helper()
	dir := t.TempDir()
	server, _ := testTLS(t)
	cert := server.Certificates[0]
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{"tunnel.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), "tunnel.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "tunnel.token": []byte(hex.EncodeToString(bytes.Repeat([]byte{42}, 32)))} {
		if e := os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	freeAddr := func() string {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		a := l.Addr().String()
		l.Close()
		return a
	}
	return tunnelConfig{Name: "test", Mode: "server", Tunnel: freeAddr(), Local: freeAddr(), TokenFile: filepath.Join(dir, "tunnel.token"), CertFile: filepath.Join(dir, "tunnel.crt"), KeyFile: filepath.Join(dir, "tunnel.key"), CAFile: filepath.Join(dir, "tunnel.crt"), Carriers: 2, Streams: 4}
}
func TestPanelConfigPersistenceRollbackAndValidation(t *testing.T) {
	p, c, csrf := testPanel(t)
	config := testConfigFiles(t)
	w := requestPanel(p, c, csrf, "POST", "/api/config", config)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var d map[string]string
	json.Unmarshal(w.Body.Bytes(), &d)
	config.ID = d["id"]
	loaded, e := newPanel(context.Background(), p.path, "a-long-test-password-only", false)
	if e != nil || loaded.tunnels[config.ID] == nil {
		t.Fatal("config not persisted", e)
	}
	bad := config
	bad.Streams = 129
	w = requestPanel(p, c, csrf, "POST", "/api/config", bad)
	if w.Code != 400 {
		t.Fatal("invalid capacity accepted")
	}
	originalPath := p.path
	p.path = filepath.Join(t.TempDir(), "missing-parent-file", "panel.json")
	os.WriteFile(filepath.Dir(p.path), []byte("block directory creation"), 0600)
	config.Name = "must rollback"
	w = requestPanel(p, c, csrf, "POST", "/api/config", config)
	if w.Code != 500 || p.tunnels[config.ID].config.Name != "test" {
		t.Fatal("save failure changed configuration")
	}
	p.path = originalPath
	w = requestPanel(p, c, "", "GET", "/api/backup", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), strings.Repeat("2a", 32)) {
		t.Fatal("backup includes secret or failed")
	}
	w = requestPanel(p, c, csrf, "POST", "/api/action", map[string]string{"id": config.ID, "action": "delete"})
	if w.Code != 200 || len(p.tunnels) != 0 {
		t.Fatal("delete failed")
	}
}
func TestManagedTunnelEndToEndAndStop(t *testing.T) {
	p, c, csrf := testPanel(t)
	config := testConfigFiles(t)
	config.Enabled = true
	w := requestPanel(p, c, csrf, "POST", "/api/config", config)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	serverID := result["id"]
	backend, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Close()
	go func() {
		for {
			conn, e := backend.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	agent := config
	agent.ID = ""
	agent.Name = "agent"
	agent.Mode = "agent"
	agent.Local = backend.Addr().String()
	w = requestPanel(p, c, csrf, "POST", "/api/config", agent)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	agentID := result["id"]
	defer p.stop(serverID)
	defer p.stop(agentID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		n := p.tunnels[serverID].stats.carriers.Load()
		p.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("carriers not connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, e := net.DialTimeout("tcp", config.Local, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("panel-live-test")
	if _, e = conn.Write(payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(conn, got); e != nil || !bytes.Equal(payload, got) {
		t.Fatal("relay failed", e)
	}
	w = requestPanel(p, c, "", "GET", "/api/status", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	p.mu.Lock()
	stats := p.tunnels[serverID].stats
	p.mu.Unlock()
	if stats.sent.Load() < int64(len(payload)) || stats.received.Load() < int64(len(payload)) || stats.active.Load() < 1 {
		t.Fatal("missing traffic metrics")
	}
	config.ID = serverID
	w = requestPanel(p, c, csrf, "POST", "/api/config", config)
	if w.Code != 409 {
		t.Fatal("edited a running tunnel")
	}
	w = requestPanel(p, c, csrf, "POST", "/api/action", map[string]string{"id": serverID, "action": "stop"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	p.mu.Lock()
	running := p.tunnels[serverID].running
	p.mu.Unlock()
	if running {
		t.Fatal("stop returned before tunnel exit")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = conn.Read(make([]byte, 1)); e == nil {
		t.Fatal("live stream survived stop")
	}
}
func TestPanelRemoteRequiresTLS(t *testing.T) {
	e := runPanel(context.Background(), []string{"-listen", "0.0.0.0:9090"})
	if e == nil || !strings.Contains(e.Error(), "HTTPS") {
		t.Fatal("remote plaintext panel allowed", e)
	}
}

func TestPanelSessionExpiryAndBoundedLogs(t *testing.T) {
	p, c, _ := testPanel(t)
	p.mu.Lock()
	s := p.sessions[c.Value]
	s.expires = time.Now().Add(-time.Second)
	p.sessions[c.Value] = s
	p.mu.Unlock()
	if w := requestPanel(p, c, "", "GET", "/api/status", nil); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
	stats := &tunnelStats{}
	ctx := context.WithValue(context.Background(), metricKey{}, stats)
	for i := 0; i < 200; i++ {
		event(ctx, "event %d", i)
	}
	if len(stats.logs) != 120 || !strings.Contains(stats.logs[119], "event 199") {
		t.Fatal("log retention broken")
	}
}
func TestPanelBindFailureIsVisible(t *testing.T) {
	p, c, csrf := testPanel(t)
	config := testConfigFiles(t)
	listener, e := net.Listen("tcp", config.Tunnel)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	config.Enabled = true
	w := requestPanel(p, c, csrf, "POST", "/api/config", config)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var d map[string]string
	json.Unmarshal(w.Body.Bytes(), &d)
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.mu.Lock()
		tunnel := p.tunnels[d["id"]]
		running, message := tunnel.running, tunnel.lastError
		p.mu.Unlock()
		if !running && message != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bind failure not reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
