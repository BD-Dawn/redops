#!/bin/bash
set -e

echo "[*] Setting up REDOPS Red Team Agent..."

cd "$(dirname "$0")"

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# Run PDF ingestion
echo "[*] Ingesting PDFs into vector store..."
python3 ingest.py

echo ""
echo "[+] Setup complete! Run the agent with:"
echo "    python3 $(pwd)/main.py"
echo ""
echo "    Or set your target first:"
echo "    python3 $(pwd)/main.py --target 10.10.10.0/24 --scope 'Internal pentest - ACME Corp'"
