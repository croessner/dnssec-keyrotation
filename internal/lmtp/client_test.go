package lmtp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/model"
)

func TestSendUsesLMTPAndContainsStableEventID(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	done := make(chan string, 1)
	go fakeServer(serverSide, done)
	cfg := config.LMTP{Enabled: true, Address: "192.0.2.50:24", Hostname: "ns1.example.test", From: "dnssec@example.test", To: []string{"admin@example.test"}, Timeout: 2 * time.Second}
	client := NewWithDialer(cfg, func(context.Context, string, string) (net.Conn, error) { return clientSide, nil })
	event := model.Notification{ID: "event-123", Zone: "example.test.", Kind: model.KindZSK, CompletedAt: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), OldKeyID: 1, NewKeyID: 2}
	if err := client.Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	body := <-done
	if !strings.Contains(body, "Message-ID: <event-123@ns1.example.test>") || !strings.Contains(body, "Zone: example.test.") {
		t.Fatalf("unexpected message: %s", body)
	}
}

func TestSendRejectsZoneHeaderInjectionBeforeDial(t *testing.T) {
	dialed := false
	cfg := config.LMTP{Enabled: true, Address: "192.0.2.50:24", Hostname: "ns1.example.test", From: "dnssec@example.test", To: []string{"admin@example.test"}, Timeout: 2 * time.Second}
	client := NewWithDialer(cfg, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, context.Canceled
	})
	event := model.Notification{ID: "event-123", Zone: "example.test.\r\nBcc: attacker@example.net", Kind: model.KindZSK, CompletedAt: time.Now()}
	if err := client.Send(context.Background(), event); err == nil {
		t.Fatal("header-injection zone accepted")
	}
	if dialed {
		t.Fatal("LMTP connection attempted before event validation")
	}
}

func fakeServer(conn net.Conn, done chan<- string) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("220 test LMTP ready\r\n"))
	for _, response := range []string{"250-test\r\n250 8BITMIME\r\n", "250 2.1.0 ok\r\n", "250 2.1.5 ok\r\n", "354 send data\r\n"} {
		_, _ = reader.ReadString('\n')
		_, _ = conn.Write([]byte(response))
	}
	var body strings.Builder
	for {
		line, _ := reader.ReadString('\n')
		if line == ".\r\n" {
			break
		}
		body.WriteString(line)
	}
	_, _ = conn.Write([]byte("250 2.0.0 delivered\r\n"))
	_, _ = reader.ReadString('\n')
	_, _ = conn.Write([]byte("221 bye\r\n"))
	done <- body.String()
}
