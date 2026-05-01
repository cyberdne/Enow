#!/bin/bash
pkill -f cloudflared
rm -f t1.log t2.log
nohup cloudflared tunnel --url http://127.0.0.1:1431 > t1.log 2>&1 &
nohup cloudflared tunnel --url http://127.0.0.1:1430 > t2.log 2>&1 &
echo "Sabar Gus, lagi narik link Cloudflare..."
sleep 15
echo "--- LINK DASHBOARD (1431) ---"
grep -a 'trycloudflare.com' t1.log | tail -n 1
echo "--- LINK CHAT (1430) ---"
grep -a 'trycloudflare.com' t2.log | tail -n 1
