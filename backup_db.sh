#!/bin/bash
cd /home/cattle/ai-secscan
mkdir -p data/backups
BACKUP_FILE="data/backups/secscan_$(date +%Y%m%d_%H%M%S).sql.gz"
sudo docker compose exec -T postgres pg_dump -U secscan -d secscan --clean --if-exists | gzip > "$BACKUP_FILE"
find data/backups -name "secscan_*.sql.gz" -mtime +7 -delete
echo "Backup created: $BACKUP_FILE"
