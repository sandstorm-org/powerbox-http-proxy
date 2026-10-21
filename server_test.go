package main

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type responseRoundTripper func(*http.Request) (*http.Response, error)

func (f responseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestConnectResponseFraming(t *testing.T) {
	spoofer, err := GenSpoofer()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	storage, err := NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetTokenFor("https://example.com", "test-token"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(storage, spoofer)
	const body = "article body"
	for _, tc := range []struct {
		name          string
		contentLength int64
		chunked       bool
		close         bool
	}{
		{"unknown length with close", -1, false, true},
		{"unknown length without framing", -1, false, false},
		{"known length with close", int64(len(body)), false, true},
		{"chunked keep alive", -1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// getTransportFor uses DefaultTransport. These subtests must remain serial.
			originalTransport := http.DefaultTransport
			http.DefaultTransport = responseRoundTripper(func(req *http.Request) (*http.Response, error) {
				resp := &http.Response{
					StatusCode: http.StatusOK,
					ProtoMajor: 1, ProtoMinor: 1,
					Header:        make(http.Header),
					ContentLength: tc.contentLength,
					Close:         tc.close,
					Body:          io.NopCloser(strings.NewReader(body)),
					Request:       req,
				}
				if tc.chunked {
					resp.TransferEncoding = []string{"chunked"}
				}
				return resp, nil
			})
			defer func() { http.DefaultTransport = originalTransport }()
			done := make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				defer close(done)
				srv.handleConnect(w, req)
			}))
			defer proxy.Close()
			conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				conn.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("CONNECT handler did not exit")
				}
			}()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			connectResp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
			if err != nil {
				t.Fatal(err)
			}
			if connectResp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT status = %d", connectResp.StatusCode)
			}
			// The test uses the locally generated spoofed certificate.
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			defer tlsConn.Close()
			reader := bufio.NewReader(tlsConn)
			requests := 1
			if tc.chunked {
				requests = 2
			}
			for i := 0; i < requests; i++ {
				req, err := http.NewRequest("GET", "https://example.com/article", nil)
				if err != nil {
					t.Fatal(err)
				}
				// End the keep-alive case cleanly after proving tunnel reuse.
				req.Close = i == 1
				if err := req.Write(tlsConn); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(reader, req)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatalf("reading response body (received %q): %v", got, err)
				}
				if string(got) != body {
					t.Fatalf("body = %q, want %q", got, body)
				}
			}
			// A known-length body completes without EOF; separately verify closure.
			if _, err := reader.ReadByte(); err != io.EOF {
				t.Fatalf("after response: got %v, want EOF", err)
			}
		})
	}
}
