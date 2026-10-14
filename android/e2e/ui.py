"""ui.py <serial> dump | tap <regex> | wait <regex> [seconds]: list the screen's texts, tap the first
node whose text, content description, or resource ID matches, or wait for one to appear. The e2e
driver uses it to enrol a fingerprint through Settings."""

import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ADB = os.environ.get("ADB", "adb")


def nodes(serial):
    subprocess.run([ADB, "-s", serial, "shell", "uiautomator dump /sdcard/ui.xml"], capture_output=True)
    xml = subprocess.run([ADB, "-s", serial, "shell", "cat /sdcard/ui.xml"], capture_output=True, text=True).stdout
    if "<" not in xml:
        return []
    return list(ET.fromstring(xml[xml.index("<"):]).iter("node"))


def find(serial, pattern):
    pat = re.compile(pattern, re.I)
    for n in nodes(serial):
        if any(pat.search(n.get(k) or "") for k in ("text", "content-desc", "resource-id")):
            return n
    return None


def main():
    serial, cmd = sys.argv[1], sys.argv[2]
    if cmd == "dump":
        for n in nodes(serial):
            if n.get("text") or n.get("content-desc"):
                print(repr(n.get("text")), n.get("content-desc"), n.get("resource-id"))
    elif cmd == "tap":
        n = find(serial, sys.argv[3])
        if n is None:
            sys.exit(1)
        x1, y1, x2, y2 = map(int, re.findall(r"\d+", n.get("bounds")))
        subprocess.run([ADB, "-s", serial, "shell", f"input tap {(x1 + x2) // 2} {(y1 + y2) // 2}"])
    elif cmd == "wait":
        deadline = time.time() + float(sys.argv[4] if len(sys.argv) > 4 else 10)
        while time.time() < deadline:
            if find(serial, sys.argv[3]) is not None:
                return
            time.sleep(1)
        sys.exit(1)


main()
