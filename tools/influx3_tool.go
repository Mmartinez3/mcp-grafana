package influx3

import (
    "context"
    "github.com/grafana/mcp-grafana/pkg/toolapi"
)

func AddInflux3Tools(server *toolapi.Server, client *Client) {
    server.MustRegister("get_server_uptime", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        host := params["host"].(string)
        desde := params["desde"].(string)
        hasta := params["hasta"].(string)
        return client.GetServerUptime(ctx, host, desde, hasta)
    })
    
}
