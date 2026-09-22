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

# --hostname part.salikh.info --backend http://192.168.1.11:8080/ --port 443  --http-port 80
# Parse arguments
HOSTNAME="part.salikh.info"
BACKEND="http://192.168.1.11:8080"
PORT="443"
HTTP_PORT="80"
CACHE_DIR=""
SELF_SIGNED_DIR=""
CERT_FILE=""
KEY_FILE=""
NO_TLS=""
SELF_SIGNED=""
VERBOSE="1"

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
        --self-signed)
            SELF_SIGNED="-self-signed"
            shift
            ;;
        --self-signed-dir)
            SELF_SIGNED_DIR="$2"
            shift 2
            ;;
        --cert)
            CERT_FILE="$2"
            shift 2
            ;;
        --key)
            KEY_FILE="$2"
            shift 2
            ;;
        --no-tls)
            NO_TLS="-no-tls"
            shift
            ;;
        --verbose)
            VERBOSE="-verbose"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use: $0 [--hostname HOSTNAME] [--backend URL] [--port PORT] [--http-port PORT] [--cache-dir DIR] [--self-signed] [--self-signed-dir DIR] [--cert FILE] [--key FILE] [--no-tls] [--verbose]"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$BACKEND" ]; then
    echo "Error: --backend is required"
    exit 1
fi

if [ -z "$NO_TLS" ] && [ -z "$HOSTNAME" ]; then
    echo "Error: --hostname is required for HTTPS mode (use --no-tls for HTTP-only mode)"
    exit 1
fi

# Build command
CMD="$BINARY -backend=$BACKEND"

if [ -n "$NO_TLS" ]; then
    CMD="$CMD $NO_TLS -http-port=$HTTP_PORT"
else
    CMD="$CMD -hostname=$HOSTNAME -port=$PORT -http-port=$HTTP_PORT"

    if [ -n "$SELF_SIGNED" ]; then
        CMD="$CMD $SELF_SIGNED"
        if [ -n "$SELF_SIGNED_DIR" ]; then
            CMD="$CMD -self-signed-dir=$SELF_SIGNED_DIR"
        fi
    elif [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; then
        CMD="$CMD -cert=$CERT_FILE -key=$KEY_FILE"
    else
        # Let's Encrypt is default
        if [ -n "$CACHE_DIR" ]; then
            CMD="$CMD -cache-dir=$CACHE_DIR"
        fi
    fi
fi

if [ -n "$VERBOSE" ]; then
    CMD="$CMD $VERBOSE"
fi

# Display configuration
if [ -n "$NO_TLS" ]; then
    echo "Starting HTTP proxy..."
    echo "  Backend: $BACKEND"
    echo "  HTTP Port: $HTTP_PORT"
else
    echo "Starting HTTPS proxy..."
    echo "  Hostname: $HOSTNAME"
    echo "  Backend: $BACKEND"
    echo "  HTTPS Port: $PORT"
    echo "  HTTP Port (ACME/Redirect): $HTTP_PORT"

    if [ -n "$SELF_SIGNED" ]; then
        echo "  Mode: Self-signed"
        if [ -n "$SELF_SIGNED_DIR" ]; then
            echo "  Cert Dir: $SELF_SIGNED_DIR"
        fi
    elif [ -n "$CERT_FILE" ]; then
        echo "  Mode: Manual certificate"
        echo "  Cert: $CERT_FILE"
    else
        echo "  Mode: Let's Encrypt"
        if [ -n "$CACHE_DIR" ]; then
            echo "  Cache Dir: $CACHE_DIR"
        fi
    fi
fi

if [ -n "$VERBOSE" ]; then
    echo "  Verbose: enabled"
fi

echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run the binary
exec $CMD
