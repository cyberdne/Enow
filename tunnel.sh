#!/bin/bash

# Matikan proses lama biar gak bentrok
sudo pkill -f cloudflared

# Hapus log lama
rm -f tunnel1431.log tunnel1430.log

echo "------------------------------------------"
echo "Menjalankan Tunnel Port 1431 & 1430..."
echo "------------------------------------------"

# Jalankan Tunnel Dashboard (1431)
nohup cloudflared tunnel --url http://127.0.0.1:1431 > tunnel1431.log 2>&1 &

# Jalankan Tunnel Chat (1430)
nohup cloudflared tunnel --url http://127.0.0.1:1430 > tunnel1430.log 2>&1 &

echo "Sabar Gus, nunggu link jadi (10 detik)..."
sleep 10

echo "=========================================="
echo "         LINK AKSES ENOWX AI              "
echo "=========================================="

# Ambil link 1431
LINK1431=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' tunnel1431.log | tail -n 1)
echo "DASHBOARD (1431): $LINK1431"

# Ambil link 1430
LINK1430=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' tunnel1430.log | tail -n 1)
echo "CHAT (1430)     : $LINK1430"
echo "=========================================="
echo "Tunnel sudah jalan di background (aman)."
