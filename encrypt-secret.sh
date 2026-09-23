#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/https-proxy"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Building..."
    cd "$SCRIPT_DIR"
    bash build.sh
fi

INPUT_FILE="${1:-$SCRIPT_DIR/secret.json}"
OUTPUT_FILE="${2:-${INPUT_FILE}.enc}"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input secret file '$INPUT_FILE' not found."
    echo "Usage: $0 [input_secret.json] [output_secret.json.enc]"
    exit 1
fi

exec "$BINARY" -encrypt-secret "$INPUT_FILE" -encrypt-secret-out "$OUTPUT_FILE" "${@:3}"
