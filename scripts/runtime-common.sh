#!/usr/bin/env bash
# Shared by installers, local development and service launchers. Bash 3.2 compatible.
fail() { printf 'Tally: %s\n' "$*" >&2; exit 1; }
progress() { printf 'Tally: %s\n' "$*"; }
# Package managers append labels such as "(Homebrew)" or "(Ubuntu ...)".
postgres_major_version() {
    local banner="$1" pattern='^postgres \(PostgreSQL\) ([0-9]+)([. ][^[:cntrl:]]*)?$'
    [[ "$banner" =~ $pattern ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}
load_env() {
    local line key
    [ -f "$1" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        key="${line%%=*}"
        [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || fail "Invalid configuration key in $1"
        [ "$key" != "$line" ] || fail "Expected KEY=value in $1"
        # Configuration is data, never shell code. Shell environment overrides the file.
        if ! printenv "$key" >/dev/null 2>&1; then export "$line"; fi
    done < "$1"
}
write_env() {
    local key value
    for key in "$@"; do
        value="${!key}"
        case "$value" in *$'\n'*|*$'\r'*) fail "Newlines are not allowed in $key" ;; esac
        printf '%s=%s\n' "$key" "$value"
    done
}
xml_escape() { local value="$1"; value="${value//&/\&amp;}"; value="${value//</\&lt;}"; value="${value//>/\&gt;}"; value="${value//\"/\&quot;}"; printf '%s' "$value"; }
# Each service executes a private wrapper; this handles paths with spaces without shell evaluation.
write_service() {
    local name="$1" command="$2" unit plist keepalive='<true/>'
    if [ "$name" = server ]; then keepalive='<dict><key>SuccessfulExit</key><false/></dict>'; fi
    if [ "$(uname -s)" = Darwin ]; then
        plist="$HOME/Library/LaunchAgents/ai.godel.tally.$name.plist"
        mkdir -p "$(dirname "$plist")"
        cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>ai.godel.tally.$name</string>
<key>ProgramArguments</key><array><string>/bin/bash</string><string>$(xml_escape "$command")</string></array>
<key>ExitTimeOut</key><integer>90</integer>
<key>AbandonProcessGroup</key><false/>
<key>RunAtLoad</key><true/><key>KeepAlive</key>$keepalive<key>ThrottleInterval</key><integer>10</integer>
<key>StandardOutPath</key><string>$(xml_escape "$TALLY_DATA_DIR/$name.log")</string>
<key>StandardErrorPath</key><string>$(xml_escape "$TALLY_DATA_DIR/$name.log")</string>
</dict></plist>
PLIST
    else
        unit="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/tally-$name.service"
        mkdir -p "$(dirname "$unit")"
        # systemd expands % specifiers even inside quotes, and uses C-style escaping.
        command="${command//\\/\\\\}"; command="${command//\"/\\\"}"; command="${command//%/%%}"; command="${command//\$/\$\$}"
        cat > "$unit" <<UNIT
[Unit]
Description=Gödel Tally $name
After=network-online.target
[Service]
Type=simple
ExecStart=/bin/bash "$command"
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=90
UMask=0077
[Install]
WantedBy=default.target
UNIT
    fi
}
# launchctl bootout returns before the job and its supervised databases have stopped. Until
# launchd forgets the job, bootstrap fails and kickstart targets the job being removed.
wait_for_launchd_removal() {
    local label="gui/$(id -u)/ai.godel.tally.$1" attempt
    for attempt in $(seq 1 120); do
        launchctl print "$label" >/dev/null 2>&1 || return 0
        sleep 1
    done
    return 1
}
start_service() {
    local name="$1" attempt
    if [ "$(uname -s)" = Darwin ]; then
        if ! launchctl print "gui/$(id -u)/ai.godel.tally.$name" >/dev/null 2>&1; then
            for attempt in $(seq 1 10); do
                launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/ai.godel.tally.$name.plist" 2>/dev/null && break
                [ "$attempt" != 10 ] || fail "Could not register ai.godel.tally.$name with launchd."
                sleep 1
            done
        fi
        launchctl kickstart "gui/$(id -u)/ai.godel.tally.$name"
    else
        systemctl --user daemon-reload
        systemctl --user enable --now "tally-$name.service"
    fi
}
