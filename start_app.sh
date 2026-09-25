#!/bin/bash

echo "🚀 Starting PhishGuard Web Application Pipeline..."

# Start the Python ML Model in the background
echo "🧠 Starting Python Machine Learning Model (Port 8000)..."
(cd ../model && uvicorn app:app --host 127.0.0.1 --port 8000) &
PYTHON_PID=$!

# Start the Node.js Orchestrator
echo "⚙️  Starting Node.js Backend Orchestrator (Port 3000)..."
# Optional: Set your VirusTotal API key here if you have one
# export VIRUSTOTAL_API_KEY="your_vt_api_key_here"
node server.js &
NODE_PID=$!

echo ""
echo "✅ Both backend servers are now running smoothly!"
echo "🛑 Press [CTRL+C] at any time to shut everything down."

# Catch the exit signal (CTRL+C) to safely kill both servers at once
trap "echo 'Shutting down servers...'; kill $PYTHON_PID $NODE_PID; exit" INT TERM EXIT

# Wait to keep the terminal active
wait
