#!/bin/bash
echo "=== Simple AlloyDB Connection Test ==="
echo "1. Environment check..."
echo "   Hostname: $(hostname)"
echo "   User: $(whoami)"

echo "2. Testing metadata service..."
curl -s -H "Metadata-Flavor: Google" --connect-timeout 5 \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" && echo "" || echo "Failed to reach metadata service"

echo "3. Testing psql availability..."
which psql || echo "psql not found"

echo "4. Testing basic psql connection (will fail but shows error)..."
PGPASSWORD="dummy" timeout 5 psql -h 10.109.0.14 -p 5432 -U postgres -d postgres -c "SELECT 1;" 2>&1 || true

echo "=== Test complete ==="