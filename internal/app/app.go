// Package app assembles and runs the DNSSEC key-rotation controller.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/croessner/dnssec-keyrotation/internal/autodns"
	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/control"
	"github.com/croessner/dnssec-keyrotation/internal/controller"
	"github.com/croessner/dnssec-keyrotation/internal/dnsprobe"
	"github.com/croessner/dnssec-keyrotation/internal/lmtp"
	"github.com/croessner/dnssec-keyrotation/internal/pdns"
	"github.com/croessner/dnssec-keyrotation/internal/state"
	"go.uber.org/fx"
)

// Run starts the controller and local control server until ctx is canceled.
func Run(ctx context.Context, cfg config.Config) error {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	app := fx.New(
		fx.Supply(cfg),
		fx.Provide(newLogger, newState, newPDNS, newAutoDNS, newObserver, newNotifier, newController, newServer),
		fx.Invoke(func(lc fx.Lifecycle, c *controller.Controller, s *control.Server, log *slog.Logger) {
			lc.Append(fx.Hook{OnStart: func(context.Context) error {
				ln, err := s.Prepare()
				if err != nil {
					return err
				}
				wg.Add(2)
				go func() {
					defer wg.Done()
					if err := s.Serve(runCtx, ln); err != nil {
						log.Error("control server stopped", "error", err)
						errCh <- err
					}
				}()
				go func() {
					defer wg.Done()
					if err := c.Run(runCtx); err != nil {
						log.Error("controller stopped", "error", err)
						errCh <- err
					}
				}()
				return nil
			}, OnStop: func(context.Context) error { cancelRun(); wg.Wait(); return nil }})
		}),
		fx.NopLogger,
	)
	if err := app.Start(ctx); err != nil {
		return err
	}
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
		cancelRun()
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := app.Stop(stopCtx); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

func newLogger(cfg config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
func newState(cfg config.Config, lc fx.Lifecycle) (*state.Store, error) {
	s, err := state.Open(cfg.Controller.StateFile)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.Hook{OnStop: func(context.Context) error { return s.Close() }})
	return s, nil
}
func newPDNS(cfg config.Config) (pdns.API, error) {
	key, err := config.ReadSecret(cfg.PowerDNS.APIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("powerdns credential: %w", err)
	}
	hc := &http.Client{Timeout: cfg.PowerDNS.Timeout, Transport: &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConnsPerHost: 2}}
	return pdns.New(cfg.PowerDNS.URL, cfg.PowerDNS.ServerID, key, hc), nil
}
func newAutoDNS(cfg config.Config) (autodns.API, error) {
	password, err := config.ReadSecret(cfg.AutoDNS.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("autodns credential: %w", err)
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	hc := &http.Client{Timeout: cfg.AutoDNS.Timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("autodns redirects are forbidden") }}
	return autodns.New(cfg.AutoDNS.URL, cfg.AutoDNS.Username, password, cfg.AutoDNS.Context, cfg.AutoDNS.MinimumRequestInterval, hc), nil
}
func newObserver(cfg config.Config) dnsprobe.Observer {
	return dnsprobe.New(cfg.DNS.Resolvers, cfg.DNS.AuthoritativeServers, cfg.DNS.LocalAuthoritative, cfg.DNS.Timeout)
}
func newNotifier(cfg config.Config) controller.Notifier {
	return lmtp.New(cfg.Notifications.LMTP)
}
func newController(cfg config.Config, p pdns.API, r autodns.API, o dnsprobe.Observer, s *state.Store, log *slog.Logger, notifier controller.Notifier) *controller.Controller {
	c := controller.New(cfg, p, r, o, s, log)
	c.SetNotifier(notifier)
	return c
}
func newServer(cfg config.Config, c *controller.Controller, log *slog.Logger) *control.Server {
	return control.New(c, cfg.Controller.Socket, log)
}
