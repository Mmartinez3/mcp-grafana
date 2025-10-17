package main

import (
    "context"
    "errors"
    "flag"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "slices"
    "strings"
    "syscall"
    "time"

    "github.com/mark3labs/mcp-go/server"

    mcpgrafana "github.com/grafana/mcp-grafana"
    "github.com/grafana/mcp-grafana/tools"
    "github.com/grafana/mcp-grafana/tools/influx3"
)

func maybeAddTools(s *server.MCPServer, tf func(*server.MCPServer), enabledTools []string, disable bool, category string) {
    if !slices.Contains(enabledTools, category) {
        slog.Debug("Not enabling tools", "category", category)
        return
    }
    if disable {
        slog.Info("Disabling tools", "category", category)
        return
    }
    slog.Debug("Enabling tools", "category", category)
    tf(s)
}

type disabledTools struct {
    enabledTools string

    search, datasource, incident,
    prometheus, loki, alerting,
    dashboard, folder, oncall, asserts, sift, admin,
    pyroscope, navigation bool
}

type localGrafanaConfig struct {
    debug bool

    tlsCertFile   string
    tlsKeyFile    string
    tlsCAFile     string
    tlsSkipVerify bool

    EnableInflux3 bool
    Influx3URL    string
    Influx3Token  string
    Influx3Bucket string
    Influx3UseSQL bool
}

func (dt *disabledTools) addFlags() {
    flag.StringVar(&dt.enabledTools, "enabled-tools", "search,datasource,incident,prometheus,loki,alerting,dashboard,folder,oncall,asserts,sift,admin,pyroscope,navigation", "A comma separated list of tools enabled for this server.")
    flag.BoolVar(&dt.search, "disable-search", false, "Disable search tools")
    flag.BoolVar(&dt.datasource, "disable-datasource", false, "Disable datasource tools")
    flag.BoolVar(&dt.incident, "disable-incident", false, "Disable incident tools")
    flag.BoolVar(&dt.prometheus, "disable-prometheus", false, "Disable prometheus tools")
    flag.BoolVar(&dt.loki, "disable-loki", false, "Disable loki tools")
    flag.BoolVar(&dt.alerting, "disable-alerting", false, "Disable alerting tools")
    flag.BoolVar(&dt.dashboard, "disable-dashboard", false, "Disable dashboard tools")
    flag.BoolVar(&dt.folder, "disable-folder", false, "Disable folder tools")
    flag.BoolVar(&dt.oncall, "disable-oncall", false, "Disable oncall tools")
    flag.BoolVar(&dt.asserts, "disable-asserts", false, "Disable asserts tools")
    flag.BoolVar(&dt.sift, "disable-sift", false, "Disable sift tools")
    flag.BoolVar(&dt.admin, "disable-admin", false, "Disable admin tools")
    flag.BoolVar(&dt.pyroscope, "disable-pyroscope", false, "Disable pyroscope tools")
    flag.BoolVar(&dt.navigation, "disable-navigation", false, "Disable navigation tools")
}

func (gc *localGrafanaConfig) addFlags() {
    flag.BoolVar(&gc.debug, "debug", false, "Enable debug mode for the Grafana transport")
    flag.StringVar(&gc.tlsCertFile, "tls-cert-file", "", "Path to TLS certificate file for client authentication")
    flag.StringVar(&gc.tlsKeyFile, "tls-key-file", "", "Path to TLS private key file for client authentication")
    flag.StringVar(&gc.tlsCAFile, "tls-ca-file", "", "Path to TLS CA certificate file for server verification")
    flag.BoolVar(&gc.tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (insecure)")

    flag.BoolVar(&gc.EnableInflux3, "enable-influx3", false, "Enable InfluxDB 3 tool")
    flag.StringVar(&gc.Influx3URL, "influx3-url", "", "URL de InfluxDB 3")
    flag.StringVar(&gc.Influx3Token, "influx3-token", "", "Token de acceso para InfluxDB 3")
    flag.StringVar(&gc.Influx3Bucket, "influx3-bucket", "telegraf", "Bucket de InfluxDB para consultas (default telegraf)")
    flag.BoolVar(&gc.Influx3UseSQL, "influx3-use-sql", true, "Usar SQL para consultas (si no, usar InfluxQL)")
}

func (dt *disabledTools) addTools(s *server.MCPServer) {
    enabledTools := strings.Split(dt.enabledTools, ",")
    maybeAddTools(s, tools.AddSearchTools, enabledTools, dt.search, "search")
    maybeAddTools(s, tools.AddDatasourceTools, enabledTools, dt.datasource, "datasource")
    maybeAddTools(s, tools.AddIncidentTools, enabledTools, dt.incident, "incident")
    maybeAddTools(s, tools.AddPrometheusTools, enabledTools, dt.prometheus, "prometheus")
    maybeAddTools(s, tools.AddLokiTools, enabledTools, dt.loki, "loki")
    maybeAddTools(s, tools.AddAlertingTools, enabledTools, dt.alerting, "alerting")
    maybeAddTools(s, tools.AddDashboardTools, enabledTools, dt.dashboard, "dashboard")
    maybeAddTools(s, tools.AddFolderTools, enabledTools, dt.folder, "folder")
    maybeAddTools(s, tools.AddOnCallTools, enabledTools, dt.oncall, "oncall")
    maybeAddTools(s, tools.AddAssertsTools, enabledTools, dt.asserts, "asserts")
    maybeAddTools(s, tools.AddSiftTools, enabledTools, dt.sift, "sift")
    maybeAddTools(s, tools.AddAdminTools, enabledTools, dt.admin, "admin")
    maybeAddTools(s, tools.AddPyroscopeTools, enabledTools, dt.pyroscope, "pyroscope")
    maybeAddTools(s, tools.AddNavigationTools, enabledTools, dt.navigation, "navigation")
}

func newServer(dt disabledTools) *server.MCPServer {
    s := server.NewMCPServer("mcp-grafana", mcpgrafana.Version(), server.WithInstructions(`
    This server provides access to your Grafana instance and the surrounding ecosystem.
    `))
    dt.addTools(s)
    return s
}

type tlsConfig struct {
    certFile, keyFile string
}

func (tc *tlsConfig) addFlags() {
    flag.StringVar(&tc.certFile, "server.tls-cert-file", "", "Path to TLS certificate file for server HTTPS")
    flag.StringVar(&tc.keyFile, "server.tls-key-file", "", "Path to TLS private key file for server HTTPS")
}

type httpServer interface {
    Start(addr string) error
    Shutdown(ctx context.Context) error
}

func runHTTPServer(ctx context.Context, srv httpServer, addr, transportName string) error {
    serverErr := make(chan error, 1)
    go func() {
        if err := srv.Start(addr); err != nil {
            serverErr <- err
        }
        close(serverErr)
    }()

    select {
    case err := <-serverErr:
        return err
    case <-ctx.Done():
        slog.Info(fmt.Sprintf("%s server shutting down...", transportName))
        shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer shutdownCancel()

        if err := srv.Shutdown(shutdownCtx); err != nil {
            return fmt.Errorf("shutdown error: %v", err)
        }
        select {
        case err := <-serverErr:
            if err != nil && !errors.Is(err, http.ErrServerClosed) {
                return fmt.Errorf("server error during shutdown: %v", err)
            }
        case <-shutdownCtx.Done():
            slog.Warn(fmt.Sprintf("%s server did not stop gracefully", transportName))
        }
    }

    return nil
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
}

func run(transport, addr, basePath, endpointPath string, logLevel slog.Level, dt disabledTools, gcConfig localGrafanaConfig, tls tlsConfig) error {
    slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{ Level: logLevel })))
    s := newServer(dt)

    // Inicialización de cliente Influx3 si habilitado
    var influx3Client *influx3.Client
    if gcConfig.EnableInflux3 {
        var err error
        influx3Client, err = influx3.NewClient(gcConfig.Influx3URL, gcConfig.Influx3Token, gcConfig.Influx3Bucket, gcConfig.Influx3UseSQL)
        if err != nil {
            return fmt.Errorf("failed to init influx3 client: %w", err)
        }
    }

    // registrar herramientas existentes
    dt.addTools(s)

    // registrar Influx3
    if gcConfig.EnableInflux3 {
        tools.AddInflux3Tools(s, influx3Client)
    }

    // convertir localGrafanaConfig a mcpgrafana.GrafanaConfig
    grafCfg := mcpgrafana.GrafanaConfig{ Debug: gcConfig.debug }
    if gcConfig.tlsCertFile != "" || gcConfig.tlsKeyFile != "" || gcConfig.tlsCAFile != "" || gcConfig.tlsSkipVerify {
        grafCfg.TLSConfig = &mcpgrafana.TLSConfig{
            CertFile:   gcConfig.tlsCertFile,
            KeyFile:    gcConfig.tlsKeyFile,
            CAFile:     gcConfig.tlsCAFile,
            SkipVerify: gcConfig.tlsSkipVerify,
        }
    }

    // ahora disparar servidor
    switch transport {
    case "stdio":
        srv := server.NewStdioServer(s)
        srv.SetContextFunc(mcpgrafana.ComposedStdioContextFunc(grafCfg))
        slog.Info("Starting via stdio", "version", mcpgrafana.Version())
        if err := srv.Listen(context.Background(), os.Stdin, os.Stdout); err != nil && err != context.Canceled {
            return fmt.Errorf("server error: %v", err)
        }
        return nil

    case "sse":
        httpSrv := &http.Server{ Addr: addr }
        srv := server.NewSSEServer(s,
            server.WithSSEContextFunc(mcpgrafana.ComposedSSEContextFunc(grafCfg)),
            server.WithStaticBasePath(basePath),
            server.WithHTTPServer(httpSrv),
        )
        mux := http.NewServeMux()
        if basePath == "" {
            basePath = "/"
        }
        mux.Handle(basePath, srv)
        mux.HandleFunc("/healthz", handleHealthz)
        httpSrv.Handler = mux
        slog.Info("Starting SSE", "version", mcpgrafana.Version(), "address", addr)
        return runHTTPServer(context.Background(), srv, addr, "SSE")

    case "streamable-http":
        httpSrv := &http.Server{ Addr: addr }
        opts := []server.StreamableHTTPOption{
            server.WithHTTPContextFunc(mcpgrafana.ComposedHTTPContextFunc(grafCfg)),
            server.WithStateLess(true),
            server.WithEndpointPath(endpointPath),
            server.WithStreamableHTTPServer(httpSrv),
        }
        if tls.certFile != "" || tls.keyFile != "" {
            opts = append(opts, server.WithTLSCert(tls.certFile, tls.keyFile))
        }
        srv := server.NewStreamableHTTPServer(s, opts...)
        mux := http.NewServeMux()
        mux.Handle(endpointPath, srv)
        mux.HandleFunc("/healthz", handleHealthz)
        httpSrv.Handler = mux
        slog.Info("Starting streamable-http", "version", mcpgrafana.Version(), "address", addr)
        return runHTTPServer(context.Background(), srv, addr, "StreamableHTTP")

    default:
        return fmt.Errorf("invalid transport type: %s", transport)
    }
}

func main() {
    var transport string
    flag.StringVar(&transport, "t", "stdio", "Transport type (stdio, sse or streamable-http)")
    flag.StringVar(&transport, "transport", "stdio", "Transport type (stdio, sse or streamable-http)")
    addr := flag.String("address", "localhost:8000", "Host:port for server")
    basePath := flag.String("base-path", "", "Base path for sse")
    endpointPath := flag.String("endpoint-path", "/mcp", "Endpoint for streamable-http")
    logLevel := flag.String("log-level", "info", "Log level")
    showVersion := flag.Bool("version", false, "Print version and exit")

    var dt disabledTools
    dt.addFlags()
    var gc localGrafanaConfig
    gc.addFlags()
    var tlsCfg tlsConfig
    tlsCfg.addFlags()

    flag.Parse()

    if *showVersion {
        fmt.Println(mcpgrafana.Version())
        os.Exit(0)
    }

    if err := run(transport, *addr, *basePath, *endpointPath, parseLevel(*logLevel), dt, gc, tlsCfg); err != nil {
        panic(err)
    }
}

func parseLevel(level string) slog.Level {
    var l slog.Level
    if err := l.UnmarshalText([]byte(level)); err != nil {
        return slog.LevelInfo
    }
    return l
}
