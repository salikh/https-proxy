#!/bin/bash
set -e

# Default values
HOSTNAME=""
OUTPUT_DIR=""
DAYS=365
KEY_SIZE=2048

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --days)
            DAYS="$2"
            shift 2
            ;;
        --key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --hostname HOSTNAME [--output-dir DIR] [--days DAYS] [--key-size BITS]"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$HOSTNAME" ]; then
    echo "Error: --hostname is required"
    echo "Usage: $0 --hostname HOSTNAME [--output-dir DIR] [--days DAYS] [--key-size BITS]"
    exit 1
fi

# Set default output directory
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$(pwd)/certs"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

CERT_FILE="$OUTPUT_DIR/cert.pem"
KEY_FILE="$OUTPUT_DIR/key.pem"

echo "Generating self-signed certificate for: $HOSTNAME"
echo "Output directory: $OUTPUT_DIR"
echo "Validity: $DAYS days"
echo "Key size: $KEY_SIZE bits"
echo ""

# Generate private key and certificate
openssl req -x509 \
    -newkey rsa:$KEY_SIZE \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days $DAYS \
    -nodes \
    -subj "/CN=$HOSTNAME" \
    -addext "subjectAltName=DNS:$HOSTNAME,DNS:*.$HOSTNAME"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Self-signed certificate generated successfully!"
    echo ""
    echo "Certificate: $CERT_FILE"
    echo "Key:         $KEY_FILE"
    echo ""
    echo "To use with the proxy:"
    echo "  ./start.sh --hostname $HOSTNAME --backend http://YOUR_BACKEND --self-signed --self-signed-dir $OUTPUT_DIR"
    echo ""
    echo "Certificate details:"
    openssl x509 -in "$CERT_FILE" -text -noout | grep -A 2 "Subject:\|Not Before\|Not After\|Subject Alternative Name"
else
    echo "Error: Failed to generate certificate"
    exit 1
fi
