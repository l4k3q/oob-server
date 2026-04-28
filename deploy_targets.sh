#!/bin/bash
# Rebuild and restart the target lab stack after source changes
set -e

cd /root/oobserver-next

echo "[targets] git pull..."
git pull

echo "[targets] rebuilding vulnlab image (multi-stage Maven build, ~3min)..."
docker compose -f docker-compose.target.yml build --no-cache vulnlab

echo "[targets] restarting vulnlab + log4shell..."
docker compose -f docker-compose.target.yml up -d vulnlab log4shell

echo "[targets] waiting 15s for services to start..."
sleep 15

echo "[targets] status:"
docker compose -f docker-compose.target.yml ps vulnlab log4shell

echo "[targets] done."
