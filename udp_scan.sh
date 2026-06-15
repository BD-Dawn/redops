#!/usr/bin/env bash
# udp_scan.sh — Non-blocking UDP nmap wrapper for the recon agent.
# Always runs in the background. Writes PID and results to the evidence dir.
#
# Usage: udp_scan.sh <target> [top_ports] [extra_nmap_flags...]
#   target     — IP, CIDR, or hostname
#   top_ports  — number of top UDP ports (default: 50)
#
# Examples:
#   udp_scan.sh 10.10.10.5
#   udp_scan.sh 10.10.10.0/24 200
#   udp_scan.sh 10.10.10.5 100 -T2

set -u

TARGET="${1:?Usage: udp_scan.sh <target> [top_ports] [extra_flags...]}"
TOP_PORTS="${2:-50}"
shift 2 2>/dev/null || shift 1

EVIDENCE_DIR="${EVIDENCE_DIR:-/home/kali/OffensiveAI/evidence}"
mkdir -p "$EVIDENCE_DIR"

OUTFILE="$EVIDENCE_DIR/udp_scan"
PIDFILE="$EVIDENCE_DIR/.udp_scan.pid"
DONEFILE="$EVIDENCE_DIR/.udp_scan.done"

# Kill any previous UDP scan still running
if [ -f "$PIDFILE" ]; then
    OLD_PID=$(cat "$PIDFILE" 2>/dev/null)
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[udp_scan] Killing previous UDP scan (PID $OLD_PID)"
        kill "$OLD_PID" 2>/dev/null
        wait "$OLD_PID" 2>/dev/null
    fi
    rm -f "$PIDFILE" "$DONEFILE"
fi

echo "[udp_scan] Starting background UDP scan: $TARGET (top $TOP_PORTS ports)"
echo "[udp_scan] Results will be in: $OUTFILE.nmap"
echo "[udp_scan] Check status: cat $EVIDENCE_DIR/.udp_scan.done"

# Launch in background
(
    nmap -sU --top-ports "$TOP_PORTS" -T3 --max-retries 2 \
        -oA "$OUTFILE" "$@" "$TARGET" >/dev/null 2>&1
    echo "completed $(date '+%Y-%m-%d %H:%M:%S')" > "$DONEFILE"
) &

SCAN_PID=$!
echo "$SCAN_PID" > "$PIDFILE"
echo "[udp_scan] Running in background (PID $SCAN_PID). Continue with the engagement."
