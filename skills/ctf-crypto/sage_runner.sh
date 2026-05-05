#!/bin/bash
# sage_runner.sh — Run SageMath via Docker (podman-docker)
# Usage:
#   ./sage_runner.sh script.sage        # run a .sage file
#   ./sage_runner.sh -c "factor(2^64)"  # inline expression
#   ./sage_runner.sh                    # interactive shell

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAGE_IMAGE="docker.io/sagemath/sagemath:latest"

if [[ "$1" == "-c" ]]; then
    TMPFILE=$(mktemp /tmp/_sage_inline_XXXXXX.sage)
    echo "$2" > "$TMPFILE"
    chmod 777 "$TMPFILE"
    docker run --rm \
        -v "${SCRIPT_DIR}:/work" \
        -v /tmp:/tmp \
        -w /tmp \
        "$SAGE_IMAGE" sage "$TMPFILE"
    rm -f "$TMPFILE"
elif [[ -n "$1" ]]; then
    SAGE_SCRIPT="$(realpath "$1")"
    TMPSCRIPT="/tmp/$(basename "$SAGE_SCRIPT")"
    cp "$SAGE_SCRIPT" "$TMPSCRIPT"
    chmod 777 "$TMPSCRIPT"
    docker run --rm \
        -v "${SCRIPT_DIR}:/work" \
        -v /tmp:/tmp \
        -w /tmp \
        "$SAGE_IMAGE" sage "$TMPSCRIPT"
    rm -f "$TMPSCRIPT"
else
    docker run --rm -it \
        -v "${SCRIPT_DIR}:/work" \
        -v /tmp:/tmp \
        -w /tmp \
        "$SAGE_IMAGE" sage
fi
