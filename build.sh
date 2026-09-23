#!/bin/bash
set -e

function @verbose() { echo "$@" >&2; "$@"; }

echo "Building HTTPS proxy..." >&2
@verbose go build -o https-proxy
echo "Setting low port capability on binary..." >&2
@verbose sudo setcap 'cap_net_bind_service=+ep' ./https-proxy

echo "✓ Build successful: ./https-proxy"
echo ""
echo "Usage: ./start.sh [options]"
echo ""
echo "Options:"
echo "  --hostname HOSTNAME      Hostname for HTTPS server (required)"
echo "  --backend URL           Backend HTTP address to proxy to (required)"
echo "  --port PORT             HTTPS port (default: 443)"
echo "  --http-port PORT        HTTP port for ACME challenges and HTTPS redirects (default: 80)"
echo "  --cache-dir DIR         Certificate cache directory (default: ~/.cache/https-proxy)"
echo "  --verbose               Enable verbose request logging"
echo ""
echo "Example:"
echo "  ./start.sh --hostname example.com --backend http://localhost:8080"
