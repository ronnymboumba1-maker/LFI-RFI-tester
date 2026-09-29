#!/bin/bash
set -e
echo "[*] Installation LFI/RFI Attacker v1.0"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo ""
echo "[+] OK"
echo "    source venv/bin/activate"
echo "    python lfi_rfi_attacker.py"