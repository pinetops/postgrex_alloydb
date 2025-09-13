#!/bin/bash
LOG_FILE=/var/log/alloydb-test.log
exec 1>>$LOG_FILE 2>&1

echo "=== AlloyDB Connection Test Started at $(date) ==="

# Install required packages
echo "Installing PostgreSQL client..."
apt-get update && apt-get install -y postgresql-client curl

# Get service account info
echo "Checking service account..."
SA_EMAIL=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email")
echo "Service Account: $SA_EMAIL"

# Get OAuth token
echo "Getting OAuth token..."
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | sed -n 's/.*"access_token":"\([^"]*\).*/\1/p')
echo "Token obtained: ${TOKEN:0:30}..."

# Test direct connection to AlloyDB
echo "Testing direct connection to AlloyDB..."
echo "Host: 10.109.0.14"
echo "Port: 5432"

# Test with different username formats
echo "Testing with full service account name..."
PGPASSWORD="$TOKEN" psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com" \
  -d postgres \
  -c "SELECT current_user, version();" 2>&1 || echo "Failed with full name: $?"

echo "Testing with just service account name..."
PGPASSWORD="$TOKEN" psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgrex-ci-sa" \
  -d postgres \
  -c "SELECT current_user;" 2>&1 || echo "Failed with short name: $?"

echo "Testing with .iam suffix..."
PGPASSWORD="$TOKEN" psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgrex-ci-sa@postgrex-alloydb-ci.iam" \
  -d postgres \
  -c "SELECT current_user;" 2>&1 || echo "Failed with .iam suffix: $?"

# Download and test with AlloyDB proxy
echo "Downloading AlloyDB proxy..."
wget https://storage.googleapis.com/alloydb-auth-proxy/v1.12.2/alloydb-auth-proxy.linux.amd64 -O /usr/local/bin/alloydb-auth-proxy
chmod +x /usr/local/bin/alloydb-auth-proxy

echo "Starting AlloyDB proxy..."
/usr/local/bin/alloydb-auth-proxy \
  "projects/postgrex-alloydb-ci/locations/us-central1/clusters/postgrex-ci-cluster/instances/postgrex-ci-primary" \
  --port=5433 &
PROXY_PID=$!
sleep 5

echo "Testing connection through proxy..."
PGPASSWORD="$TOKEN" psql \
  -h localhost \
  -p 5433 \
  -U "postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com" \
  -d postgres \
  -c "SELECT current_user, version();" 2>&1 || echo "Failed through proxy: $?"

kill $PROXY_PID

echo "=== Test completed at $(date) ==="

# Keep the log accessible via serial console
tail -f $LOG_FILE