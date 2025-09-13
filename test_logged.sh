#!/bin/bash
LOG=/tmp/test.log

{
  echo "=== AlloyDB Connection Test Started at $(date) ==="
  echo "1. Environment check..."
  echo "   Hostname: $(hostname)"
  echo "   User: $(whoami)"
  
  echo "2. Service account check..."
  SA_EMAIL=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 5 \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>&1)
  echo "   Service Account: $SA_EMAIL"
  
  echo "3. Getting OAuth token..."
  TOKEN_RESPONSE=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 5 \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>&1)
  TOKEN=$(echo "$TOKEN_RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\).*/\1/p')
  
  if [ -n "$TOKEN" ]; then
    echo "   Token obtained: ${TOKEN:0:30}..."
    
    echo "4. Testing AlloyDB connection with IAM auth..."
    echo "   Connecting to: 10.109.0.14:5432"
    echo "   Username: postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com"
    
    PGPASSWORD="$TOKEN" psql \
      -h 10.109.0.14 \
      -p 5432 \
      -U "postgrex-ci-sa@postgrex-alloydb-ci.iam.gserviceaccount.com" \
      -d postgres \
      -c "SELECT current_user, version();" 2>&1 || echo "   Connection failed: $?"
  else
    echo "   Failed to get OAuth token"
    echo "   Response: $TOKEN_RESPONSE"
  fi
  
  echo "=== Test completed at $(date) ==="
} | tee $LOG

# Output to stdout as well
cat $LOG

# Exit successfully so we can see the logs
exit 0