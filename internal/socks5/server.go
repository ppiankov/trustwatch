// Package socks5 provides a minimal SOCKS5 CONNECT-only server.
// It exists so the trustwatch image can double as its own tunnel relay
// in air-gapped clusters that cannot pull a dedicated proxy image.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	authNone      = 0x00
	authNoAccept  = 0xFF

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repHostUnreachable  = 0x04
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// Server is a minimal SOCKS5 proxy that only supports the CONNECT command
// with no authentication. It resolves DNS on the server side, which is the
// whole point — the relay pod runs inside the cluster where cluster DNS works.
type Server struct {
	Addr string // listen address, default ":1080"
}

// ListenAndServe starts the SOCKS5 server. It blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.Addr
	if addr == "" {
		addr = ":1080"
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	// Shut down listener when context is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	log.Printf("socks5 listening on %s", ln.Addr())

	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Phase 1: version/method negotiation
	if err := s.negotiate(conn); err != nil {
		return
	}

	// Phase 2: read CONNECT request and relay
	s.handleRequest(conn)
}

// negotiate performs the SOCKS5 version/method handshake.
func (s *Server) negotiate(conn net.Conn) error {
	// Read version + number of methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return errors.New("not SOCKS5")
	}

	// Read method list
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// We only support no-auth (0x00)
	for _, m := range methods {
		if m == authNone {
			_, err := conn.Write([]byte{socks5Version, authNone})
			return err
		}
	}

	conn.Write([]byte{socks5Version, authNoAccept}) //nolint:errcheck // closing anyway
	return errors.New("no acceptable auth method")
}

// handleRequest reads a SOCKS5 request, dials the target, and relays data.
func (s *Server) handleRequest(conn net.Conn) {
	// Read version, cmd, reserved, address type
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	if header[1] != cmdConnect {
		s.sendReply(conn, repCmdNotSupported)
		return
	}

	// Parse destination address
	addr, err := s.readAddr(conn, header[3])
	if err != nil {
		s.sendReply(conn, repAddrNotSupported)
		return
	}

	// Dial the target
	target, err := net.Dial("tcp", addr)
	if err != nil {
		rep := byte(repGeneralFailure)
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			if opErr.Op == "dial" {
				rep = repHostUnreachable
			}
		}
		s.sendReply(conn, rep)
		return
	}
	defer target.Close()

	s.sendReply(conn, repSuccess)

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(target, conn) //nolint:errcheck // relay best-effort
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, target) //nolint:errcheck // relay best-effort
	}()
	wg.Wait()
}

// readAddr parses a SOCKS5 address based on the address type byte.
func (s *Server) readAddr(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		host = string(domain)
	default:
		return "", fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}

	// Read 2-byte port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// sendReply writes a minimal SOCKS5 reply with the given status code.
// Bound address is always 0.0.0.0:0 since the client doesn't use it.
func (s *Server) sendReply(conn net.Conn, rep byte) {
	// version(1) + rep(1) + rsv(1) + atyp(1) + addr(4) + port(2) = 10
	reply := []byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	conn.Write(reply) //nolint:errcheck // best-effort reply
}
