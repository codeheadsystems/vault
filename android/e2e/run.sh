#!/usr/bin/env bash
# The Android end-to-end run (docs/android.md, Build and tests): the instrumented E2eTest steps
# against a real `vault serve` and the CLI, on one emulator.
#
# Preconditions: one emulator or device as ANDROID_SERIAL (or the only one adb sees), with a PIN of
# 1234 and fingerprint 1 enrolled (adb emu finger touch 1 works on the emulator), ANDROID_HOME and
# JAVA_HOME set, and cargo on the PATH. FIREFOX_APK, when set, is installed for the web fill step;
# otherwise the step is skipped unless Firefox is already installed.
#
# Usage: android/e2e/run.sh

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ANDROID_DIR=$(dirname "$HERE")
REPO=$(dirname "$ANDROID_DIR")
ADB="${ANDROID_HOME:?}/platform-tools/adb"
export ADB
SERIAL=${ANDROID_SERIAL:-$("$ADB" devices | awk 'NR > 1 && $2 == "device" { print $1; exit }')}
[ -n "$SERIAL" ] || { echo "no device" >&2; exit 2; }
export ANDROID_SERIAL=$SERIAL
A=("$ADB" -s "$SERIAL")
PORT=${VAULT_E2E_PORT:-18443}
WEB_PORT=${VAULT_E2E_WEB_PORT:-18081}
PW="correct horse battery staple"
PW2="second horse battery staple"
PW3="third horse battery staple"
APP=com.codeheadsystems.vault
RUNNER=$APP.test/androidx.test.runner.AndroidJUnitRunner

WORK=$(mktemp -d)
PIDS=()
WATCHER=
cleanup() {
    local status=$?
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    # The finger watcher runs in its own process group: end all of it, logcat included.
    if [ -n "$WATCHER" ]; then kill -- "-$WATCHER" 2>/dev/null || true; fi
    rm -rf "$WORK"
    if [ "$status" -ne 0 ]; then echo "e2e FAILED (exit $status)" >&2; fi
    exit "$status"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

step() { printf '\n== %s\n' "$*"; }

# The server, with a self-signed certificate; the emulator reaches the host's loopback at 10.0.2.2.
step "vault serve"
(cd "$REPO" && cargo build --locked -q -p vault-cli)
VAULT="$REPO/target/debug/vault"
"$VAULT" serve init --data "$WORK/srv" --url "https://10.0.2.2:$PORT" --listen "127.0.0.1:$PORT" >/dev/null
"$VAULT" serve --data "$WORK/srv" >"$WORK/serve.log" 2>&1 &
PIDS+=($!)
PHONE_SETUP=$("$VAULT" serve token add phone --data "$WORK/srv" | grep -o 'vault://[^ ]*')
CLI_SETUP=$("$VAULT" serve token add cli --data "$WORK/srv" --url "https://127.0.0.1:$PORT" | grep -o 'vault://[^ ]*')
CLI_TOKEN=$(sed 's/.*token=\([A-Z0-9]*\).*/\1/' <<<"$CLI_SETUP")
sleep 1

# The CLI, with its own data directory and no agent.
mkdir -m 700 -p "$WORK/cli/data" "$WORK/cli/config" "$WORK/cli/run"
export XDG_DATA_HOME="$WORK/cli/data" XDG_CONFIG_HOME="$WORK/cli/config" XDG_RUNTIME_DIR="$WORK/cli/run" VAULT_NO_AGENT=1
cli() { local pw=$1; shift; "$VAULT" "$@" --password-fd 3 3<<<"$pw"; }

step "vault init"
mkfifo "$WORK/in"
"$VAULT" init --password-fd 3 --kit "$WORK/kit.txt" 3< <(printf '%s\n%s\n' "$PW" "$PW") <"$WORK/in" >"$WORK/init.log" 2>&1 &
INIT=$!
exec 4>"$WORK/in"
echo "$CLI_SETUP" >&4
for _ in $(seq 60); do [ -s "$WORK/kit.txt" ] && break; sleep 0.5; done
SK=$(grep -o 'VLT1-[A-Z0-9-]*' "$WORK/kit.txt")
echo "${SK##*-}" >&4
exec 4>&-
wait "$INIT"
echo "cli-pass" | cli "$PW" add cli-item-1 --username cli-user >/dev/null
echo "e2e-pass" | cli "$PW" add e2e-app --username e2e-user --uri "androidapp://com.codeheadsystems.vault.e2etarget" >/dev/null
echo "web-pass" | cli "$PW" add e2e-web --username web-user --uri "http://10.0.2.2:$WEB_PORT" >/dev/null

# A login page for the web fill.
mkdir "$WORK/web"
cat >"$WORK/web/login.html" <<'EOF'
<!doctype html><html><head><meta name="viewport" content="width=device-width"></head><body>
<form action="done.html" method="get"><input id="username" name="username" autocomplete="username" style="font-size:32px">
<input id="password" name="password" type="password" autocomplete="current-password" style="font-size:32px">
<button type="submit" style="font-size:32px">Sign in</button></form></body></html>
EOF
echo '<!doctype html><html><body><h1>Signed in</h1></body></html>' >"$WORK/web/done.html"
python3 -I -m http.server "$WEB_PORT" --bind 127.0.0.1 --directory "$WORK/web" >/dev/null 2>&1 &
PIDS+=($!)

step "unlock the device"
# After a boot the user stays locked until the PIN is entered; nothing of the app can start before.
"${A[@]}" shell input keyevent 224
sleep 1
"${A[@]}" shell input keyevent 82
sleep 2
"${A[@]}" shell input text 1234
"${A[@]}" shell input keyevent 66
for _ in $(seq 20); do "${A[@]}" shell dumpsys user | grep -q RUNNING_UNLOCKED && break; sleep 1; done
"${A[@]}" shell dumpsys user | grep -q RUNNING_UNLOCKED || fail "the device did not unlock with PIN 1234"
"${A[@]}" shell input keyevent 3

step "install"
(cd "$ANDROID_DIR" && ./gradlew -q :app:installDebug :app:installDebugAndroidTest :e2e-target:installDebug)
[ -n "${FIREFOX_APK:-}" ] && "${A[@]}" install -r "$FIREFOX_APK" >/dev/null
"${A[@]}" shell pm clear "$APP" >/dev/null
"${A[@]}" shell settings put secure autofill_service "$APP/.autofill.VaultAutofillService"
WEB_ARGS=()
if "${A[@]}" shell pm path org.mozilla.firefox >/dev/null 2>&1; then
    # A fresh profile each run: no restored tab with an earlier run's typed values.
    "${A[@]}" shell pm clear org.mozilla.firefox >/dev/null
    WEB_ARGS=(-e webUrl "http://10.0.2.2:$WEB_PORT/login.html")
fi

# Touches the emulator's fingerprint sensor whenever a test asks for it in the log. It runs in a
# new session with no hold on this script's output, so cleanup can end the whole group.
"${A[@]}" logcat -c
setsid "$HERE/finger-watch.sh" "$ADB" "$SERIAL" </dev/null >/dev/null 2>&1 &
WATCHER=$!

run() {
    step "$1"
    local out
    out=$("${A[@]}" shell "am instrument -w -e class com.codeheadsystems.vault.E2eTest#$1 \
        -e setup '$PHONE_SETUP' -e sk '$SK' -e pw '$PW' -e pw2 '$PW2' -e pw3 '$PW3' ${WEB_ARGS[*]} $RUNNER")
    grep -q "^OK (1 test)" <<<"$out" || fail "$1:
$out"
    echo "ok"
}

# Waits up to $2 seconds for the resumed activity to match $1.
wait_activity() {
    local deadline=$((SECONDS + $2))
    while [ $SECONDS -lt $deadline ]; do
        "${A[@]}" shell dumpsys activity activities | grep -m1 topResumedActivity | grep -qE "$1" && return 0
        sleep 1
    done
    fail "no activity matching $1: $("${A[@]}" shell dumpsys activity activities | grep -m1 topResumedActivity)"
}

# Enrols fingerprint $1 through Settings, with the lock screen PIN 1234. The vault's autofill
# service stays on: it refuses Settings, so it must not cover the PIN field.
enrol_finger() {
    "${A[@]}" shell am force-stop com.android.settings
    "${A[@]}" shell am start -a android.settings.FINGERPRINT_ENROLL >/dev/null
    wait_activity 'ConfirmLock' 15
    python3 -I "$HERE/ui.py" "$SERIAL" wait 'password_entry' 10 || fail "no PIN field"
    "${A[@]}" shell input text 1234
    "${A[@]}" shell input keyevent 66
    wait_activity 'Fingerprint|Enroll' 15
    for _ in 1 2 3 4 5; do python3 -I "$HERE/ui.py" "$SERIAL" tap '^(more|i agree|agree|next|start|continue)$' || break; sleep 2; done
    for _ in $(seq 14); do "${A[@]}" emu finger touch "$1" >/dev/null; sleep 0.7; "${A[@]}" emu finger remove "$1" >/dev/null; sleep 0.7; done
    python3 -I "$HERE/ui.py" "$SERIAL" wait 'Fingerprint added' 10 || fail "the fingerprint was not added"
    python3 -I "$HERE/ui.py" "$SERIAL" tap '^done$' || true
    "${A[@]}" shell input keyevent 3
}

run e01_setup
echo "cli-pass-2" | cli "$PW" add cli-item-2 >/dev/null
run e02_refusals
# Only the launcher activity and the autofill service are exported: the shell cannot start the picker.
AM=$("${A[@]}" shell am start -n "$APP/.autofill.PickerActivity" 2>&1 || true)
grep -q "not exported" <<<"$AM" || fail "the picker started from the shell: $AM"
echo "picker refused from the shell: ok"
run e03_unlockPullsAndPushes
cli "$PW" sync >/dev/null
LS=$(cli "$PW" ls)
grep -q phone-item <<<"$LS" || fail "the CLI did not pull phone-item"
printf '%s\n%s\n%s\n' "$PW" "$PW2" "$PW2" | "$VAULT" passwd --password-fd 0 >/dev/null
run e04_credentialChangeOnTheCli
run e05_credentialChangeHere
cli "$PW3" sync >/dev/null
LS=$(cli "$PW3" ls)
grep -q cli-item-2 <<<"$LS" || fail "the CLI did not follow the phone's credential change"
# A stolen token pushes garbage shaped like a vault file: the phone's next sync stops on integrity.
ETAG=$(curl -sk -D - -o /dev/null -H "Authorization: Bearer $CLI_TOKEN" "https://127.0.0.1:$PORT/v1/vault" | awk -F': ' 'tolower($1) == "etag" { print $2 }' | tr -d '\r')
{ printf 'VAULT'; head -c $((4269 - 5)) /dev/urandom; } >"$WORK/garbage"
curl -sk -o /dev/null -w '%{http_code}\n' -X PUT -H "Authorization: Bearer $CLI_TOKEN" -H "If-Match: $ETAG" --data-binary @"$WORK/garbage" "https://127.0.0.1:$PORT/v1/vault"
run e06_recovery
run e07_restore
run e08_biometricUnlock
run e08b_pickerBiometricUnlockBindsAfterItsPull
# Emulator fingerprints are numbered from 1; the next unused one is the count plus one. Android
# allows five, and the driver cannot delete one, so each run uses one slot until the AVD is wiped.
ENROLLED=$("${A[@]}" shell dumpsys fingerprint | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
if [ "${ENROLLED:-5}" -lt 5 ]; then
    step "enrol a new fingerprint"
    enrol_finger $((ENROLLED + 1))
    run e09_biometricInvalidatedByEnrolment
else
    step "e09_biometricInvalidatedByEnrolment SKIPPED: five fingerprints are enrolled; wipe the AVD's data to run it"
fi
run e10_idleLockAtTheNextEntryPoint
run e11_appFill
run e12_saveOffer
if [ ${#WEB_ARGS[@]} -gt 0 ]; then
    run e13_webFill
    run e13b_webSaveOffer
else
    step "e13_webFill and e13b_webSaveOffer skipped: no Firefox"
fi
run e14_clipboardClear
step "all steps passed"
