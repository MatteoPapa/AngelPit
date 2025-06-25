#!/bin/bash

echo "🚀 Starting mitmdump cluster..."

mitmdump --mode reverse:https://127.0.0.1:5001 --ssl-insecure --listen-port 8081 --certs "*=combined.pem" --set termlog_verbosity=warning --ssl-insecure &
mitmdump --mode reverse:https://127.0.0.1:5001 --ssl-insecure --listen-port 8082 --certs "*=combined.pem" --set termlog_verbosity=warning --ssl-insecure &
mitmdump --mode reverse:https://127.0.0.1:5001 --ssl-insecure --listen-port 8083 --certs "*=combined.pem" --set termlog_verbosity=warning --ssl-insecure &

echo "✅ All mitmdump instances started in background."
