// Package main is the entry point for the AISAC agent.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/cisec/aisac-agent/internal/agent"
	"github.com/cisec/aisac-agent/internal/config"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

var (
	cfgFile  string
	logLevel string
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "aisac-agent",
		Short:   "AISAC Security Response Agent",
		Long:    `AISAC Agent executes security actions ordered by the AISAC SOAR system.`,
		Version: version,
		RunE:    run,
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/etc/aisac/agent.yaml", "config file path")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "", "log level (debug, info, warn, error)")

	// Version info
	rootCmd.SetVersionTemplate(`{{.Name}} {{.Version}}
Commit: ` + commit + `
Build Date: ` + buildDate + "\n")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Setup logger
	logger := setupLogger()

	logger.Info().
		Str("version", version).
		Str("commit", commit).
		Str("build_date", buildDate).
		Msg("Starting AISAC Agent")

	// Load configuration
	cfg, err := config.LoadAgentConfig(cfgFile)
	if err != nil {
		logger.Fatal().Err(err).Str("config", cfgFile).Msg("Failed to load configuration")
	}

	// Override log level from CLI
	if logLevel != "" {
		cfg.Logging.Level = logLevel
		logger = setupLoggerWithLevel(logLevel)
	}

	// Set agent version
	agent.Version = version

	// Create agent
	a, err := agent.New(cfg, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create agent")
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		a.Shutdown()
	}()

	// Run agent
	if err := a.Run(); err != nil {
		logger.Error().Err(err).Msg("Agent error")
		return err
	}

	logger.Info().Msg("Agent stopped")
	return nil
}

func setupLogger() zerolog.Logger {
	return setupLoggerWithLevel("info")
}

func setupLoggerWithLevel(level string) zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	var l zerolog.Level
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	default:
		l = zerolog.InfoLevel
	}

	return zerolog.New(os.Stdout).
		Level(l).
		With().
		Timestamp().
		Str("service", "aisac-agent").
		Logger()
}
