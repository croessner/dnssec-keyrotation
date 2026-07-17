// Package main provides the dnssecctl command-line interface and controller process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/croessner/dnssec-keyrotation/internal/app"
	"github.com/croessner/dnssec-keyrotation/internal/config"
	"github.com/croessner/dnssec-keyrotation/internal/control"
	"github.com/croessner/dnssec-keyrotation/internal/controller"
	"github.com/croessner/dnssec-keyrotation/internal/model"
	"github.com/spf13/cobra"
)

var version = "dev"
var commit = "none"
var date = "unknown"

func main() {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	var socket string
	r := &cobra.Command{Use: "dnssecctl", Short: "DNSSEC key rotation controller and CLI", SilenceUsage: true, SilenceErrors: true}
	r.PersistentFlags().StringVar(&socket, "socket", "/run/dnssec-keyrotation/control.sock", "controller Unix socket")
	r.AddCommand(serveCmd(), versionCmd(), getCmd(&socket, "status", "/v1/status", func() any { return &controller.Status{} }), getCmd(&socket, "zones", "/v1/zones", func() any { return &[]controller.ZoneStatus{} }), planCmd(&socket), triggerCmd(&socket), resumeCmd(&socket), enrollmentCmd(&socket))
	r.AddCommand(getCmd(&socket, "audit", "/v1/audit", func() any { return &[]controller.AuditResult{} }))
	return r
}

func enrollmentCmd(socket *string) *cobra.Command {
	c := &cobra.Command{Use: "enrollment", Short: "Inspect and arm automatic initial DNSSEC enrollment"}
	c.AddCommand(getCmd(socket, "status", "/v1/status", func() any { return &controller.Status{} }), armEnrollmentCmd(socket))
	return c
}

func armEnrollmentCmd(socket *string) *cobra.Command {
	var confirm bool
	var idem string
	c := &cobra.Command{Use: "arm", Short: "Persist a one-time baseline before automatic enrollment", RunE: func(cmd *cobra.Command, _ []string) error {
		if !confirm {
			return errors.New("--confirm is required")
		}
		var out map[string]string
		if err := control.NewClient(*socket).Post(cmd.Context(), "/v1/enrollment/arm", control.ArmEnrollmentRequest{Confirm: true}, idem, &out); err != nil {
			return err
		}
		return printJSON(out)
	}}
	c.Flags().BoolVar(&confirm, "confirm", false, "confirm the production enrollment baseline")
	c.Flags().StringVar(&idem, "idempotency-key", "", "unique key of at least 16 characters")
	_ = c.MarkFlagRequired("idempotency-key")
	return c
}

func serveCmd() *cobra.Command {
	var path string
	c := &cobra.Command{Use: "serve", Short: "Run the reconciliation controller", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return app.Run(ctx, cfg)
	}}
	c.Flags().StringVarP(&path, "config", "c", "/etc/dnssec-keyrotation/config.yaml", "configuration file")
	return c
}
func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", RunE: func(*cobra.Command, []string) error {
		return printJSON(map[string]string{"version": version, "commit": commit, "date": date})
	}}
}
func getCmd(socket *string, use, path string, out func() any) *cobra.Command {
	return &cobra.Command{Use: use, RunE: func(cmd *cobra.Command, _ []string) error {
		v := out()
		if err := control.NewClient(*socket).Get(cmd.Context(), path, v); err != nil {
			return err
		}
		return printJSON(v)
	}}
}

func planCmd(socket *string) *cobra.Command {
	var kind string
	var zones []string
	c := &cobra.Command{Use: "plan", Short: "Show the exact workflow without mutation", RunE: func(cmd *cobra.Command, _ []string) error {
		k, err := parseKind(kind)
		if err != nil {
			return err
		}
		var out controller.Plan
		req := control.RotationRequest{Kind: k, Zones: normalizeZones(zones)}
		if err := control.NewClient(*socket).Post(cmd.Context(), "/v1/rotations/plan", req, "", &out); err != nil {
			return err
		}
		return printJSON(out)
	}}
	c.Flags().StringVar(&kind, "kind", "", "zsk, ksk, or split")
	c.Flags().StringSliceVar(&zones, "zone", nil, "zone name (repeat or comma-separate)")
	_ = c.MarkFlagRequired("kind")
	_ = c.MarkFlagRequired("zone")
	return c
}
func triggerCmd(socket *string) *cobra.Command {
	var kind string
	var zones []string
	var confirm bool
	var idem string
	c := &cobra.Command{Use: "trigger", Short: "Persist a confirmed manual workflow", RunE: func(cmd *cobra.Command, _ []string) error {
		if !confirm {
			return errors.New("--confirm is required")
		}
		k, err := parseKind(kind)
		if err != nil {
			return err
		}
		req := control.RotationRequest{Kind: k, Zones: normalizeZones(zones), Confirm: true}
		var out map[string]string
		if err := control.NewClient(*socket).Post(cmd.Context(), "/v1/rotations/trigger", req, idem, &out); err != nil {
			return err
		}
		return printJSON(out)
	}}
	c.Flags().StringVar(&kind, "kind", "", "zsk, ksk, or split")
	c.Flags().StringSliceVar(&zones, "zone", nil, "zone name (repeat or comma-separate)")
	c.Flags().BoolVar(&confirm, "confirm", false, "confirm production mutation")
	c.Flags().StringVar(&idem, "idempotency-key", "", "unique key of at least 16 characters")
	_ = c.MarkFlagRequired("kind")
	_ = c.MarkFlagRequired("zone")
	_ = c.MarkFlagRequired("idempotency-key")
	return c
}

func resumeCmd(socket *string) *cobra.Command {
	var zones []string
	var confirm bool
	var idem string
	c := &cobra.Command{Use: "resume", Short: "Revalidate and resume a blocked split workflow", RunE: func(cmd *cobra.Command, _ []string) error {
		if !confirm {
			return errors.New("--confirm is required")
		}
		req := control.ResumeRequest{Kind: model.KindSplit, Zones: normalizeZones(zones), Phase: model.PhaseWaitPublish, Confirm: true}
		var out map[string]string
		if err := control.NewClient(*socket).Post(cmd.Context(), "/v1/rotations/resume", req, idem, &out); err != nil {
			return err
		}
		return printJSON(out)
	}}
	c.Flags().StringSliceVar(&zones, "zone", nil, "blocked split zone (repeat or comma-separate)")
	c.Flags().BoolVar(&confirm, "confirm", false, "confirm recovery state transition")
	c.Flags().StringVar(&idem, "idempotency-key", "", "unique key of at least 16 characters")
	_ = c.MarkFlagRequired("zone")
	_ = c.MarkFlagRequired("idempotency-key")
	return c
}
func parseKind(v string) (model.Kind, error) {
	k := model.Kind(strings.ToLower(v))
	if k != model.KindZSK && k != model.KindKSK && k != model.KindSplit {
		return "", errors.New("kind must be zsk, ksk, or split")
	}
	return k, nil
}
func normalizeZones(z []string) []string {
	out := make([]string, 0, len(z))
	for _, x := range z {
		for _, v := range strings.Split(x, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}
func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

var _ = context.Background
