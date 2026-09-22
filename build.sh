#!/bin/bash
set -e

echo "Building HTTPS proxy..."
go build -o https-proxy

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
