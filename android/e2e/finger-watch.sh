#!/usr/bin/env bash
# finger-watch.sh <adb> <serial>: touches the emulator's fingerprint sensor whenever an instrumented
# test logs "finger <n>" under the VAULTE2E tag. run.sh starts it in its own session and ends the
# whole process group.

ADB=$1
SERIAL=$2
"$ADB" -s "$SERIAL" logcat -s VAULTE2E:I | while read -r line; do
    case "$line" in
        *"finger "*)
            n=${line##*finger }
            sleep 1
            "$ADB" -s "$SERIAL" emu finger touch "$n" >/dev/null
            sleep 0.5
            "$ADB" -s "$SERIAL" emu finger remove "$n" >/dev/null
            ;;
    esac
done
