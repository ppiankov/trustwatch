package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// startEchoServer starts a TCP server that echoes back whatever it receives.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) //nolint:errcheck
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// startSOCKS5 starts a SOCKS5 server on a random port and returns its address.
func startSOCKS5(t *testing.T, ctx context.Context) string {
	t.Helper()
	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := &Server{Addr: addr}
	go func() {
		if err := s.ListenAndServe(ctx); err != nil {
			t.Logf("socks5 server error: %v", err)
		}
	}()

	// Wait for server to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socks5 server did not start within 2s")
	return ""
}

func TestServer_ListenAndServe(t *testing.T) {
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socksAddr := startSOCKS5(t, ctx)

	// Connect through SOCKS5 to the echo server
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("creating SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("dialing through SOCKS5: %v", err)
	}
	defer conn.Close()

	// Send data and verify echo
	msg := []byte("hello trustwatch")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("writing through SOCKS5: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestServer_InvalidVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socksAddr := startSOCKS5(t, ctx)

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}
	defer conn.Close()

	// Send SOCKS4 version byte — should be rejected
	conn.Write([]byte{0x04, 0x01, 0x00}) //nolint:errcheck
	conn.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 16)
	_, readErr := conn.Read(buf)
	// Server should close the connection
	if readErr == nil {
		t.Error("expected connection to be closed for non-SOCKS5 version")
	}
}

func TestServer_ConnectUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socksAddr := startSOCKS5(t, ctx)

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("creating SOCKS5 dialer: %v", err)
	}

	// Connect to a port that nothing is listening on
	_, err = dialer.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		t.Error("expected error connecting to unreachable host")
	}
}

func TestServer_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	socksAddr := startSOCKS5(t, ctx)

	// Verify server is up
	conn, err := net.DialTimeout("tcp", socksAddr, time.Second)
	if err != nil {
		t.Fatalf("server not reachable: %v", err)
	}
	conn.Close()

	// Cancel context — server should shut down
	cancel()
	time.Sleep(100 * time.Millisecond)

	_, err = net.DialTimeout("tcp", socksAddr, 200*time.Millisecond)
	if err == nil {
		t.Error("expected server to be shut down after context cancel")
	}
}

func TestServer_DefaultAddr(t *testing.T) {
	s := &Server{}
	if s.Addr != "" {
		t.Errorf("expected empty Addr, got %q", s.Addr)
	}
	// The default ":1080" is applied inside ListenAndServe, not on the struct
}

func TestServer_MultipleConnections(t *testing.T) {
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socksAddr := startSOCKS5(t, ctx)

	for i := range 5 {
		dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if err != nil {
			t.Fatalf("creating SOCKS5 dialer: %v", err)
		}

		conn, err := dialer.Dial("tcp", echoAddr)
		if err != nil {
			t.Fatalf("connection %d: dialing: %v", i, err)
		}

		msg := []byte(fmt.Sprintf("msg-%d", i))
		conn.Write(msg) //nolint:errcheck
		buf := make([]byte, len(msg))
		io.ReadFull(conn, buf) //nolint:errcheck
		if string(buf) != string(msg) {
			t.Errorf("connection %d: got %q, want %q", i, buf, msg)
		}
		conn.Close()
	}
}
