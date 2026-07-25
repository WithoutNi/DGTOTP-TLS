#!/bin/bash

unset GTK_PATH
export GTK_PATH=""

RUN_COUNT=${1:-10}
REPORT_FILE="experiment_report_$(date +%Y%m%d_%H%M%S).txt"

cd build || exit 1

if [[ ! -f server_RA ]] || [[ ! -f server_AS ]] || [[ ! -f verifier ]] || [[ ! -f client ]]; then
    echo "Error: Executables not found"
    exit 1
fi

total_runs=0
success_count=0
log_dir=$(mktemp -d)

{
    echo "Experiment started: $(date)"
    echo "Total runs: $RUN_COUNT"
} >> "$REPORT_FILE"

for ((i=1; i<=RUN_COUNT; i++)); do
    echo "Run $i/$RUN_COUNT..."
    
    server_ra_log="$log_dir/server_ra_${i}.log"
    server_as_log="$log_dir/server_as_${i}.log"
    verifier_log="$log_dir/verifier_${i}.log"
    client_log="$log_dir/client_${i}.log"
    
    > "$server_ra_log"
    > "$server_as_log"
    > "$verifier_log"
    > "$client_log"
    
    # Start processes with unbuffered output
    gnome-terminal --title="Server_RA $i" -- bash -c "stdbuf -oL ./server_RA 2>&1 | tee '$server_ra_log'; read" >/dev/null 2>&1 &
    sleep 2
    
    gnome-terminal --title="Server_AS $i" -- bash -c "stdbuf -oL ./server_AS 2>&1 | tee '$server_as_log'; read" >/dev/null 2>&1 &
    sleep 2
    
    gnome-terminal --title="Verifier $i" -- bash -c "stdbuf -oL ./verifier 2>&1 | tee '$verifier_log'; read" >/dev/null 2>&1 &
    sleep 2
    
    gnome-terminal --title="Client $i" -- bash -c "stdbuf -oL ./client 2>&1 | tee '$client_log'; read" >/dev/null 2>&1 &
    
    # Wait longer for completion
    sleep 3
    
    total_runs=$((total_runs + 1))
    
    # Check for success using flexible matching
    if grep -qE "Received from RA: Verify result:success" "$verifier_log" 2>/dev/null; then
        success_count=$((success_count + 1))
        echo "Run $i: SUCCESS" >> "$REPORT_FILE"
    else
        echo "Run $i: FAILURE" >> "$REPORT_FILE"
        # Save failure details
        echo "  Verifier last 5 lines:" >> "$REPORT_FILE"
        tail -5 "$verifier_log" | sed 's/^/    /' >> "$REPORT_FILE"
    fi
    
    # Cleanup
    pkill -f "./server_RA" 2>/dev/null || true
    pkill -f "./server_AS" 2>/dev/null || true
    pkill -f "./verifier" 2>/dev/null || true
    pkill -f "./client" 2>/dev/null || true
    
    wmctrl -l 2>/dev/null | grep -E "Server_RA $i|Server_AS $i|Verifier $i|Client $i" | awk '{print $1}' | while read id; do
        wmctrl -i -c "$id" 2>/dev/null || true
    done
    
    sleep 1
done

rm -rf "$log_dir"

success_rate=$(echo "scale=2; $success_count * 100 / $total_runs" | bc 2>/dev/null || echo "0")

{
    echo "=========================================="
    echo "Experiment Complete!"
    echo "Total runs: $total_runs"
    echo "Success count: $success_count"
    echo "Success rate: $success_rate%"
} >> "$REPORT_FILE"

echo ""
echo "=========================================="
echo "Experiment Complete!"
echo "=========================================="
echo "Total runs: $total_runs"
echo "Success count: $success_count"
echo "Success rate: $success_rate%"
echo ""
echo "Detailed report saved to: $REPORT_FILE"
echo "=========================================="