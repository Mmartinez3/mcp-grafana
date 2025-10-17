package influx3

import (
    "context"
    "fmt"

    "github.com/grafana/mcp-grafana/pkg/toolapi"
)

func RegisterInflux3Tools(server *toolapi.Server, client *Client) {
    server.MustRegister("influx3_get_server_uptime", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        hv, ok := params["host"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: host")
        }
        host, ok := hv.(string)
        if !ok {
            return nil, fmt.Errorf("param host must be string")
        }

        dv, ok := params["desde"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: desde")
        }
        desde, ok := dv.(string)
        if !ok {
            return nil, fmt.Errorf("param desde must be string")
        }

        hv2, ok := params["hasta"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: hasta")
        }
        hasta, ok := hv2.(string)
        if !ok {
            return nil, fmt.Errorf("param hasta must be string")
        }

        res, err := client.GetServerUptime(ctx, host, desde, hasta)
        if err != nil {
            return nil, fmt.Errorf("influx3: GetServerUptime error: %w", err)
        }
        return res, nil
    })

    server.MustRegister("influx3_get_network_traffic", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        xv, ok := params["host_x"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: host_x")
        }
        hostX, ok := xv.(string)
        if !ok {
            return nil, fmt.Errorf("param host_x must be string")
        }

        yv, ok := params["host_y"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: host_y")
        }
        hostY, ok := yv.(string)
        if !ok {
            return nil, fmt.Errorf("param host_y must be string")
        }

        dv, ok := params["desde"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: desde")
        }
        desde, ok := dv.(string)
        if !ok {
            return nil, fmt.Errorf("param desde must be string")
        }

        hv2, ok := params["hasta"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: hasta")
        }
        hasta, ok := hv2.(string)
        if !ok {
            return nil, fmt.Errorf("param hasta must be string")
        }

        res, err := client.GetNetworkTraffic(ctx, hostX, hostY, desde, hasta)
        if err != nil {
            return nil, fmt.Errorf("influx3: GetNetworkTraffic error: %w", err)
        }
        return res, nil
    })

    // Podés registrar más funciones si lo necesitás
}
