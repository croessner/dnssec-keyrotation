// Package lmtp delivers durable controller events through LMTP.
package lmtp

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/miekg/dns"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

// Client sends validated completion events to an LMTP endpoint.
type Client struct {
	cfg  config.LMTP
	dial dialFunc
}

// New creates an LMTP client using a network dialer.
func New(cfg config.LMTP) *Client {
	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: -1}
	return &Client{cfg: cfg, dial: dialer.DialContext}
}

// NewWithDialer creates an LMTP client with a caller-provided dialer.
func NewWithDialer(cfg config.LMTP, dial dialFunc) *Client {
	return &Client{cfg: cfg, dial: dial}
}

// Send validates and delivers one completion event.
func (c *Client) Send(ctx context.Context, event model.Notification) error {
	if !c.cfg.Enabled {
		return fmt.Errorf("LMTP notifications are disabled")
	}
	if err := validateEvent(c.cfg, event); err != nil {
		return err
	}
	from, err := mailbox(c.cfg.From)
	if err != nil {
		return err
	}
	recipients := make([]string, 0, len(c.cfg.To))
	for _, value := range c.cfg.To {
		to, err := mailbox(value)
		if err != nil {
			return err
		}
		recipients = append(recipients, to)
	}
	conn, err := c.dial(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return fmt.Errorf("dial LMTP: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(c.cfg.Timeout)); err != nil {
		return err
	}
	tp := textproto.NewConn(conn)
	defer func() { _ = tp.Close() }()
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("LMTP greeting: %w", err)
	}
	if err := command(tp, 250, "LHLO %s", c.cfg.Hostname); err != nil {
		return err
	}
	if err := command(tp, 250, "MAIL FROM:<%s>", from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := command(tp, 250, "RCPT TO:<%s>", recipient); err != nil {
			return err
		}
	}
	if err := command(tp, 354, "DATA"); err != nil {
		return err
	}
	dot := tp.DotWriter()
	if _, err := io.WriteString(dot, message(c.cfg, event, from, recipients)); err != nil {
		_ = dot.Close()
		return err
	}
	if err := dot.Close(); err != nil {
		return err
	}
	for range recipients {
		if _, _, err := tp.ReadResponse(250); err != nil {
			return fmt.Errorf("LMTP delivery response: %w", err)
		}
	}
	_ = tp.PrintfLine("QUIT")
	_, _, _ = tp.ReadResponse(221)
	return nil
}

func command(tp *textproto.Conn, want int, format string, args ...any) error {
	if err := tp.PrintfLine(format, args...); err != nil {
		return err
	}
	if _, _, err := tp.ReadResponse(want); err != nil {
		return fmt.Errorf("LMTP command %s: %w", strings.Fields(format)[0], err)
	}
	return nil
}

func mailbox(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("mailbox contains line break")
	}
	a, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}
	return a.Address, nil
}

func message(cfg config.LMTP, event model.Notification, from string, recipients []string) string {
	action := "DNSSEC rotation completed"
	body := "DNSSEC key rotation completed successfully."
	if event.Kind == model.KindEnroll {
		action = "DNSSEC enrollment completed"
		body = "DNSSEC initial enrollment completed successfully."
	}
	if event.Kind == model.KindEnroll && event.Event == "blocked" {
		action = "DNSSEC enrollment blocked"
		body = "DNSSEC initial enrollment was blocked safely. Details are available in local controller status; no further registrar write was attempted."
	}
	subject := mime.QEncoding.Encode("utf-8", fmt.Sprintf("%s: %s (%s)", action, strings.TrimSuffix(event.Zone, "."), event.Kind))
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nSubject: %s\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n\r\nZone: %s\r\nType: %s\r\nCompleted: %s\r\nOld PowerDNS key ID: %d\r\nNew PowerDNS key ID: %d\r\nNew ZSK ID (split/enrollment): %d\r\nInternetX STID: %s\r\nEvent ID: %s\r\n\r\nReports never include private or public key material.\r\n", from, strings.Join(recipients, ", "), event.CompletedAt.UTC().Format(time.RFC1123Z), event.ID, cfg.Hostname, subject, body, event.Zone, event.Kind, event.CompletedAt.UTC().Format(time.RFC3339), event.OldKeyID, event.NewKeyID, event.NewZSKID, event.RegistrarSTID, event.ID)
}

func validateEvent(cfg config.LMTP, event model.Notification) error {
	if strings.ContainsAny(event.Zone, "\r\n") {
		return fmt.Errorf("notification zone contains line break")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(event.Zone)); !ok {
		return fmt.Errorf("notification zone is not a valid DNS name")
	}
	if len(event.ID) == 0 || len(event.ID) > 128 {
		return fmt.Errorf("notification event id length is invalid")
	}
	for _, r := range event.ID {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return fmt.Errorf("notification event id contains unsafe character")
		}
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(cfg.Hostname)); !ok || strings.ContainsAny(cfg.Hostname, "\r\n") {
		return fmt.Errorf("LMTP hostname is not a safe DNS name")
	}
	return nil
}
