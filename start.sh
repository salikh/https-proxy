#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/https-proxy"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Building..."
    cd "$SCRIPT_DIR"
    bash build.sh
fi

# Parse arguments
HOSTNAME=""
BACKEND=""
PORT="443"
HTTP_PORT="80"
CACHE_DIR=""
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --backend)
            BACKEND="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --http-port)
            HTTP_PORT="$2"
            shift 2
            ;;
        --cache-dir)
            CACHE_DIR="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="-verbose"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use: $0 --hostname HOSTNAME --backend URL [--port PORT] [--http-port PORT] [--cache-dir DIR] [--verbose]"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$HOSTNAME" ]; then
    echo "Error: --hostname is required"
    exit 1
fi

if [ -z "$BACKEND" ]; then
    echo "Error: --backend is required"
    exit 1
fi

# Build command
CMD="$BINARY -hostname=$HOSTNAME -backend=$BACKEND -port=$PORT -http-port=$HTTP_PORT"

if [ -n "$CACHE_DIR" ]; then
    CMD="$CMD -cache-dir=$CACHE_DIR"
fi

if [ -n "$VERBOSE" ]; then
    CMD="$CMD $VERBOSE"
fi

echo "Starting HTTPS proxy..."
echo "  Hostname: $HOSTNAME"
echo "  Backend: $BACKEND"
echo "  HTTPS Port: $PORT"
echo "  HTTP Port (ACME): $HTTP_PORT"
if [ -n "$CACHE_DIR" ]; then
    echo "  Cache Dir: $CACHE_DIR"
fi
if [ -n "$VERBOSE" ]; then
    echo "  Verbose: enabled"
fi
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run the binary
exec $CMD
