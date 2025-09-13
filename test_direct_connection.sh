#!/bin/bash
echo "Script starting..."
echo "=== Testing Direct AlloyDB Connection from Cloud Run ==="

# Get service account email
echo "1. Checking service account..."
SA_EMAIL=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 5 \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null || echo "ERROR: Not in GCP")
echo "   Service Account: $SA_EMAIL"

if [[ "$SA_EMAIL" == "ERROR: Not in GCP" ]]; then
  echo "   Not running in GCP environment, exiting..."
  exit 1
fi

# Get OAuth token
echo "2. Getting OAuth token..."
TOKEN_RESPONSE=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 5 \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\).*/\1/p')
echo "   Token obtained: ${TOKEN:0:30}..."

# Enable psql password prompt debugging
export PGCONNECT_TIMEOUT=5

# Test with psql using the token
echo "3. Testing connection with full service account name..."
PGPASSWORD="$TOKEN" timeout 10 psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com" \
  -d postgres \
  -c "SELECT current_user, version();" \
  2>&1 || echo "   Connection failed with: postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com"

echo "4. Testing with just service account name..."
PGPASSWORD="$TOKEN" timeout 10 psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgrex-ci-sa" \
  -d postgres \
  -c "SELECT current_user;" \
  2>&1 || echo "   Connection failed with: postgrex-ci-sa"

echo "5. Testing with .iam suffix..."
PGPASSWORD="$TOKEN" timeout 10 psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgrex-ci-sa@postgrex-alloydb-ci.iam" \
  -d postgres \
  -c "SELECT current_user;" \
  2>&1 || echo "   Connection failed with: postgrex-ci-sa@postgrex-alloydb-ci.iam"

echo "6. Testing with postgres user (non-IAM)..."
PGPASSWORD="" timeout 10 psql \
  -h 10.109.0.14 \
  -p 5432 \
  -U "postgres" \
  -d postgres \
  -c "SELECT current_user;" \
  2>&1 || echo "   Connection failed with: postgres"

echo "=== Test complete ==="