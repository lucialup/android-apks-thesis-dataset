#!/bin/bash

DOWNLOAD_LIST="download_list.txt"
OUTPUT_DIR="apks/benign/samples"
LOG_FILE="download_log.txt"

mkdir -p "$OUTPUT_DIR"

TOTAL=$(wc -l < "$DOWNLOAD_LIST")
CURRENT=0

echo "Starting download of $TOTAL APKs..."
echo "Output directory: $OUTPUT_DIR"

while IFS= read -r url; do
    CURRENT=$((CURRENT + 1))
    FILENAME=$(basename "$url")

    if [ -f "$OUTPUT_DIR/$FILENAME" ]; then
        echo "[$CURRENT/$TOTAL] SKIP: $FILENAME (already exists)"
        continue
    fi

    echo "[$CURRENT/$TOTAL] Downloading: $FILENAME"

    if wget -q --show-progress --timeout=60 --tries=3 -O "$OUTPUT_DIR/$FILENAME" "$url"; then
        echo "[$CURRENT/$TOTAL] SUCCESS: $FILENAME" | tee -a "$LOG_FILE"
    else
        echo "[$CURRENT/$TOTAL] FAILED: $FILENAME" | tee -a "$LOG_FILE"
        rm -f "$OUTPUT_DIR/$FILENAME"
    fi

    sleep 0.5
done < "$DOWNLOAD_LIST"

echo ""
echo "Downloaded files: $(ls -1 "$OUTPUT_DIR" | wc -l)" | tee -a "$LOG_FILE"
