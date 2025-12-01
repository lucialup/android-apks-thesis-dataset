APK_DIR="/home/luci/android-apks-dataset/apks/benign/samples"
OUTPUT_DIR="/home/luci/android-apks-dataset/ground_truth/syscall_traces"
HARVESTER_DIR="/data/local/tmp/syscall-harvester"
DURATION=60       
MONKEY_EVENTS=500    
MONKEY_THROTTLE=100  

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}


check_adb() {
    if ! adb get-state &>/dev/null; then
        log_error "ADB not connected. Please start your emulator first."
        exit 1
    fi
    log_info "ADB connected successfully"
}

check_harvester() {
    if ! adb shell "test -f ${HARVESTER_DIR}/syscall_harvester"; then
        log_error "Syscall harvester not found. Please deploy it first:"
        echo "  cd /home/luci/android-syscall-harvester && make deploy"
        exit 1
    fi
    log_info "Syscall harvester found"
}


get_package_name() {
    local apk_path="$1"
    local pkg=""

    if command -v aapt &>/dev/null; then
        pkg=$(aapt dump badging "$apk_path" 2>/dev/null | grep "^package:" | head -1 | awk -F"'" '{print $2}')
    fi

    if [ -z "$pkg" ] && command -v aapt2 &>/dev/null; then
        pkg=$(aapt2 dump badging "$apk_path" 2>/dev/null | grep "^package:" | head -1 | awk -F"'" '{print $2}')
    fi

    if [ -z "$pkg" ]; then
        pkg=$(basename "$apk_path" .apk | sed 's/_[0-9]*$//')
    fi

    echo "$pkg"
}


get_uid() {
    local package="$1"
    adb shell pm list packages -U | grep "$package" | sed 's/.*uid://'
}

collect_trace() {
    local apk_path="$1"
    local apk_name=$(basename "$apk_path")

    log_info "=========================================="
    log_info "Processing: $apk_name"
    log_info "=========================================="

    if [ ! -f "$apk_path" ]; then
        log_error "APK file not found: $apk_path"
        return 1
    fi

    log_info "Extracting package name..."
    local package=$(get_package_name "$apk_path")
    if [ -z "$package" ]; then
        log_error "Could not determine package name for $apk_name"
        return 1
    fi
    log_info "Package: $package"

    local output_file="${OUTPUT_DIR}/${package}.syscall.log"
    if [ -f "$output_file" ]; then
        log_warn "Trace already exists: $output_file (skipping)"
        return 0
    fi

    log_info "Installing APK..."
    local install_output
    install_output=$(adb install -r -g "$apk_path" 2>&1)
    if [ $? -ne 0 ]; then
        log_error "Failed to install $apk_name"
        log_error "Output: $install_output"
        return 1
    fi
    log_info "Install successful"

    log_info "Getting app UID..."
    sleep 2  # Give system time to register the package
    local uid=$(get_uid "$package")

    if [ -z "$uid" ] || [ "$uid" -lt 10000 ] 2>/dev/null; then
        log_warn "Invalid UID '$uid', trying alternative method..."
        uid=$(adb shell dumpsys package "$package" 2>/dev/null | grep "userId=" | head -1 | sed 's/[^0-9]*//g')
    fi

    if [ -z "$uid" ] || [ "$uid" -lt 10000 ] 2>/dev/null; then
        log_error "Could not get valid UID for $package (got: $uid)"
        adb uninstall "$package" &>/dev/null
        return 1
    fi
    log_info "UID: $uid"

    log_info "Starting syscall harvester..."
    adb shell "nohup ${HARVESTER_DIR}/syscall_harvester -u $uid > /data/local/tmp/trace.log 2>&1 &" </dev/null
    sleep 3 

    if ! adb shell "pgrep -f syscall_harvester" &>/dev/null; then
        log_warn "Harvester may not be running, continuing anyway..."
    fi

    log_info "Launching app..."
    adb shell am start -W -n "$package/.MainActivity" 2>/dev/null || \
    adb shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 2>/dev/null || true
    sleep 3

    log_info "Running monkey for ${DURATION}s (${MONKEY_EVENTS} events)..."
    adb shell monkey -p "$package" --pct-syskeys 0 --throttle $MONKEY_THROTTLE $MONKEY_EVENTS 2>/dev/null || true

    log_info "Waiting for trace collection..."
    sleep 10

    log_info "Stopping harvester..."
    adb shell "pkill -9 -f syscall_harvester" 2>/dev/null || true
    sleep 2

    log_info "Saving trace to: $output_file"
    adb pull /data/local/tmp/trace.log "$output_file" &>/dev/null

    local trace_lines=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log_info "Trace contains $trace_lines syscall events"

    if [ "$trace_lines" -lt 100 ]; then
        log_warn "Very few syscalls captured - app may not have been exercised properly"
    fi

    log_info "Uninstalling app..."
    adb uninstall "$package" &>/dev/null || true

    adb shell "rm -f /data/local/tmp/trace.log" &>/dev/null || true

    log_info "Done with $package"
    echo ""

    return 0
}

main() {
    mkdir -p "$OUTPUT_DIR"

    check_adb
    check_harvester

    local apk_list=()

    if [ "$1" == "--list" ] && [ -n "$2" ]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^# ]] && continue
            apk_list+=("$line")
        done < "$2"
    elif [ "$1" == "--apk" ] && [ -n "$2" ]; then
        apk_list=("$2")
    else
        for apk in "$APK_DIR"/*.apk; do
            [ -f "$apk" ] && apk_list+=("$apk")
        done
    fi

    local total=${#apk_list[@]}
    local current=0
    local success=0
    local failed=0

    log_info "Processing $total APKs..."

    log_info "First APK in list: ${apk_list[0]:-none}"
    echo ""

    for apk_path in "${apk_list[@]}"; do
        current=$((current + 1))
        echo -e "${GREEN}[$current/$total]${NC}"

        if collect_trace "$apk_path"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
    done

    echo ""
    log_info "=========================================="
    log_info "SUMMARY"
    log_info "=========================================="
    log_info "Total: $total"
    log_info "Success: $success"
    log_info "Failed: $failed"
    log_info "Traces saved to: $OUTPUT_DIR"
}

main "$@"
