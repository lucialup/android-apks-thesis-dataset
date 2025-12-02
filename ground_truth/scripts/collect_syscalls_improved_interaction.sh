APK_DIR="/home/luci/android-apks-dataset/apks/benign/samples"
OUTPUT_DIR="/home/luci/android-apks-dataset/ground_truth/syscall_traces"
HARVESTER_DIR="/data/local/tmp/syscall-harvester"
DURATION=150         # 2.5 minutes for better coverage
MONKEY_EVENTS=2000 
MONKEY_THROTTLE=70

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_adb() {
    if ! adb get-state &>/dev/null; then
        log_error "ADB not connected"
        exit 1
    fi
    log_info "ADB connected"
}

check_harvester() {
    if ! adb shell "test -f ${HARVESTER_DIR}/syscall_harvester"; then
        log_error "Syscall harvester not found. Deploy with 'make deploy'"
        exit 1
    fi
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

get_main_activity() {
    local package="$1"
    adb shell cmd package resolve-activity --brief "$package" | tail -1 | tr -d '\r'
}

# Disable status bar pull-down to prevent monkey from accessing settings
disable_status_bar() {
    log_info "Disabling status bar pull-down..."
    
    adb shell settings put global policy_control "immersive.full=*"
    adb shell cmd statusbar disable-for-setup 2>/dev/null || true
    adb shell cmd statusbar collapse 2>/dev/null || true
    adb shell settings put secure enabled_notification_listeners "" 2>/dev/null || true
}

# Pin the app task
pin_app_task() {
    local package="$1"
    log_info "Pinning app task..."

    local task_id=$(adb shell am stack list 2>/dev/null | grep "$package" | head -1 | grep -oP 'taskId=\K[0-9]+' || true)
    if [ -z "$task_id" ]; then
        task_id=$(adb shell dumpsys activity activities 2>/dev/null | grep -A2 "TaskRecord.*$package" | grep -oP 'taskId=\K[0-9]+' | head -1 || true)
    fi
    if [ -n "$task_id" ]; then
        adb shell am task lock "$task_id" 2>/dev/null || true
        log_info "Task $task_id pinned"
    else
        log_warn "Could not get task ID for pinning, goto fallback"
    fi
}

unpin_app_task() {
    adb shell am task lock stop 2>/dev/null || true
}

enable_status_bar() {
    log_info "Re-enabling status bar..."
    unpin_app_task
    adb shell cmd statusbar disable-for-setup disable 2>/dev/null || true
    adb shell settings delete global policy_control 2>/dev/null || true
}

# Ensure WiFi stays on and notification shade is collapsed
ensure_wifi_on() {
    adb shell cmd statusbar collapse 2>/dev/null || true

    local wifi_state=$(adb shell settings get global wifi_on)
    local airplane_state=$(adb shell settings get global airplane_mode_on)

    if [ "$airplane_state" == "1" ]; then
        log_warn "Airplane mode was enabled by monkey - disabling..."
        adb shell cmd connectivity airplane-mode disable
        sleep 2
    fi

    if [ "$wifi_state" != "1" ]; then
        log_warn "WiFi was disabled by monkey - re-enabling..."
        adb shell svc wifi enable
        sleep 2
    fi
}

# Trigger network activity
trigger_network() {
    local package="$1"
    log_info "Triggering network activity..."

    adb shell am start -a android.intent.action.VIEW -d "https://example.com" "$package" 2>/dev/null || true
    sleep 2

    adb shell input swipe 540 600 540 1100  # Pull gesture
    sleep 1
}

explore_ui() {
    local package="$1"
    log_info "Exploring UI..."

    for i in {1..5}; do
        adb shell input tap 100 $((350 + i * 150))
        sleep 0.5
    done

    adb shell input swipe 540 1000 540 500
    sleep 1

    adb shell input keyevent KEYCODE_MENU 2>/dev/null || true
    sleep 0.5
    adb shell input keyevent KEYCODE_BACK
    sleep 0.5
}

collect_trace() {
    local apk_path="$1"
    local apk_name=$(basename "$apk_path")

    log_info "=========================================="
    log_info "Processing: $apk_name"
    log_info "=========================================="

    [ ! -f "$apk_path" ] && { log_error "APK not found: $apk_path"; return 1; }

    local package=$(get_package_name "$apk_path")
    [ -z "$package" ] && { log_error "Could not get package name"; return 1; }
    log_info "Package: $package"

    local output_file="${OUTPUT_DIR}/${package}.syscall.log"
    [ -f "$output_file" ] && { log_warn "Trace exists (skipping)"; return 0; }

    local install_output
    install_output=$(adb install -r -g "$apk_path" 2>&1)
    [ $? -ne 0 ] && { log_error "Install failed: $install_output"; return 1; }

    sleep 2
    local uid=$(get_uid "$package")
    if [ -z "$uid" ] || [ "$uid" -lt 10000 ] 2>/dev/null; then
        uid=$(adb shell dumpsys package "$package" 2>/dev/null | grep "userId=" | head -1 | sed 's/[^0-9]*//g')
    fi
    [ -z "$uid" ] || [ "$uid" -lt 10000 ] 2>/dev/null && { log_error "Invalid UID"; adb uninstall "$package" &>/dev/null; return 1; }
    log_info "UID: $uid"

    log_info "Starting syscall harvester..."
    adb shell "nohup ${HARVESTER_DIR}/syscall_harvester -u $uid > /data/local/tmp/trace.log 2>&1 &" </dev/null
    sleep 3

    disable_status_bar

    log_info "Launching app..."
    local main_activity=$(get_main_activity "$package")
    if [ -n "$main_activity" ]; then
        adb shell am start -W "$main_activity" 2>/dev/null || true
    else
        adb shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 2>/dev/null || true
    fi
    sleep 3

    pin_app_task "$package"
    sleep 1

    log_info "Phase 1: Initial monkey exploration (500 events)..."
    adb shell monkey -p "$package" --pct-syskeys 0 --pct-appswitch 0 --pct-anyevent 0 --pct-motion 5 --pct-trackball 0 --pct-touch 80 --pct-nav 0 --pct-majornav 0 --throttle $MONKEY_THROTTLE 500 2>/dev/null || true
    adb shell am start -n "$main_activity" 2>/dev/null || adb shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 2>/dev/null || true
    ensure_wifi_on
    pin_app_task "$package"
    sleep 1

    log_info "Phase 2: Deep UI exploration..."
    explore_ui "$package"

    trigger_network "$package"

    log_info "Phase 4: Extended interaction (800 events)..."
    adb shell monkey -p "$package" --pct-syskeys 0 --pct-appswitch 0 --pct-anyevent 0 --pct-motion 5 --pct-trackball 0 --pct-touch 80 --pct-nav 0 --pct-majornav 0 --throttle $MONKEY_THROTTLE 800 2>/dev/null || true
    adb shell am start -n "$main_activity" 2>/dev/null || adb shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 2>/dev/null || true
    ensure_wifi_on
    pin_app_task "$package"
    sleep 1

    log_info "Phase 5: Final exploration (700 events)..."
    adb shell monkey -p "$package" --pct-syskeys 0 --pct-appswitch 0 --pct-anyevent 0 --pct-motion 5 --pct-trackball 0 --pct-touch 80 --pct-nav 0 --pct-majornav 0 --throttle $MONKEY_THROTTLE 700 2>/dev/null || true
    ensure_wifi_on

    log_info "Completing trace collection..."
    sleep 20

    log_info "Stopping harvester..."
    adb shell "pkill -9 -f syscall_harvester" 2>/dev/null || true
    sleep 2

    log_info "Saving trace..."
    adb pull /data/local/tmp/trace.log "$output_file" &>/dev/null

    local trace_lines=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log_info "Trace: $trace_lines syscall events"
    [ "$trace_lines" -lt 100 ] && log_warn "Low syscall count - app may not have exercised properly"

    log_info "Cleaning up..."
    enable_status_bar
    ensure_wifi_on
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
            [[ -z "$line" || "$line" =~ ^# ]] && continue
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
    local current=0 success=0 failed=0

    log_info "Processing $total APKs..."
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
    log_info "Total: $total | Success: $success | Failed: $failed"
    log_info "Traces: $OUTPUT_DIR"
}

main "$@"
