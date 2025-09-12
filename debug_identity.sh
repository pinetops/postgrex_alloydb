#!/bin/bash
echo "=== Checking service account identity ==="
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
echo ""
echo "=== Getting OAuth token ==="
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | head -c 100
echo "..."
