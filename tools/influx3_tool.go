package influx3

import (
    "context"
    "fmt"

    "github.com/grafana/mcp-grafana/tools"
)

// RegisterInflux3Tools registra las funciones/metodos que expondrás via MCP
func RegisterInflux3Tools(server *toolapi.Server, client *Client) {
    // Nombre de la herramienta dentro del namespace MCP, por ejemplo "influx3"
    // Opcionalmente podrías prefijarlo como "influx3_get_server_uptime", etc.

    server.MustRegister("influx3_get_server_uptime", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        // validaciones de parámetros
        hostVal, ok := params["host"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: host")
        }
        host, ok := hostVal.(string)
        if !ok {
            return nil, fmt.Errorf("param host must be string")
        }

        desdeVal, ok := params["desde"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: desde")
        }
        desde, ok := desdeVal.(string)
        if !ok {
            return nil, fmt.Errorf("param desde must be string")
        }

        hastaVal, ok := params["hasta"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: hasta")
        }
        hasta, ok := hastaVal.(string)
        if !ok {
            return nil, fmt.Errorf("param hasta must be string")
        }

        // Llamás al método del cliente
        result, err := client.GetServerUptime(ctx, host, desde, hasta)
        if err != nil {
            return nil, fmt.Errorf("influx3: GetServerUptime error: %w", err)
        }
        return result, nil
    })

    server.MustRegister("influx3_get_network_traffic", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        hostXVal, ok := params["host_x"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: host_x")
        }
        hostX, ok := hostXVal.(string)
        if !ok {
            return nil, fmt.Errorf("param host_x must be string")
        }

        hostYVal, ok := params["host_y"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: host_y")
        }
        hostY, ok := hostYVal.(string)
        if !ok {
            return nil, fmt.Errorf("param host_y must be string")
        }

        desdeVal, ok := params["desde"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: desde")
        }
        desde, ok := desdeVal.(string)
        if !ok {
            return nil, fmt.Errorf("param desde must be string")
        }

        hastaVal, ok := params["hasta"]
        if !ok {
            return nil, fmt.Errorf("missing parameter: hasta")
        }
        hasta, ok := hastaVal.(string)
        if !ok {
            return nil, fmt.Errorf("param hasta must be string")
        }

        result, err := client.GetNetworkTraffic(ctx, hostX, hostY, desde, hasta)
        if err != nil {
            return nil, fmt.Errorf("influx3: GetNetworkTraffic error: %w", err)
        }
        return result, nil
    })

    // Podés agregar más funciones: status general del servidor, métricas arbitrarias, etc.
}

