// Package proxy builds streaming-friendly reverse proxies to backend MCP servers.
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/samsungds/mcp-auth-gateway/internal/config"
)

// clientHeaders are headers a client must never be able to inject; the gateway
// strips them before proxying and sets its own trusted values.
var clientHeaders = []string{
	"Authorization",
	"X-MCP-Identity",
	"X-MCP-Subject",
	"X-MCP-LoginID",
	"X-MCP-Username",
	"X-MCP-Email",
	"X-MCP-Groups",
	"X-MCP-Scopes",
	"X-MCP-Request-ID",
}

// StripClientHeaders removes any spoofable identity headers from the request.
func StripClientHeaders(h http.Header) {
	for _, name := range clientHeaders {
		h.Del(name)
	}
}

// New builds a reverse proxy for a backend MCP server. It rewrites the request
// path by stripping the external path prefix and preserves streaming semantics
// (SSE / chunked / Streamable HTTP) by flushing immediately.
func New(srv config.MCPServer) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(srv.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend_url for %q: %w", srv.Name, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("backend_url for %q must be an absolute URL", srv.Name)
	}

	stripPrefix := strings.TrimRight(srv.ExternalPathPrefix, "/")

	rp := &httputil.ReverseProxy{
		// FlushInterval < 0 flushes each write immediately, which keeps SSE and
		// Streamable HTTP responses from being buffered by the proxy.
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host

			// Rewrite the outbound path: strip the external prefix so that
			// /mock/mcp -> /mcp and /mock/mcp/... -> /mcp/...
			inPath := pr.In.URL.Path
			outPath := inPath
			if srv.StripExternalPathPrefix && stripPrefix != "" {
				outPath = strings.TrimPrefix(inPath, stripPrefix)
				if !strings.HasPrefix(outPath, "/") {
					outPath = "/" + outPath
				}
			}
			pr.Out.URL.Path = singleJoiningSlash(target.Path, outPath)
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery

			// Preserve X-Forwarded-* semantics.
			pr.SetXForwarded()
		},
	}
	return rp, nil
}

func singleJoiningSlash(a, b string) string {
	a = strings.TrimRight(a, "/")
	if b == "" {
		if a == "" {
			return "/"
		}
		return a
	}
	if !strings.HasPrefix(b, "/") {
		b = "/" + b
	}
	return a + b
}
