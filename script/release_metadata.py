#!/usr/bin/env python3
"""Apply the reviewed release configuration to the assembled production bundle."""
import base64
import json
from pathlib import Path
import plistlib
import re
import sys

ROOT = Path(__file__).resolve().parent.parent

def configuration():
    config = json.loads((ROOT / "release/version.json").read_text())
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", config["version"]):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[1-9][0-9]*", config["build"]):
        raise ValueError("invalid release build")
    if len(base64.b64decode(config["publicEDKey"], validate=True)) != 32:
        raise ValueError("invalid Sparkle public key")
    if config["feedURL"] != "https://github.com/ai-ecoverse/sliccy-app/releases/latest/download/appcast.xml":
        raise ValueError("unexpected update feed")
    return config

if __name__ == "__main__":
    config = configuration()
    if len(sys.argv) == 2 and sys.argv[1] == "--version":
        print(config["version"])
    else:
        path = Path(sys.argv[1])
        plist = plistlib.loads(path.read_bytes())
        release = sys.argv[2] == "release"
        # Proof variants keep their original version/pins and never run the updater.
        if sys.argv[2] != "proof":
            plist.update(CFBundleShortVersionString=config["version"], CFBundleVersion=config["build"])
        plist.update(SUFeedURL=config["feedURL"], SUPublicEDKey=config["publicEDKey"],
                     SUEnableAutomaticChecks=True, SUAutomaticallyUpdate=False,
                     SUAllowsAutomaticUpdates=False, SUSendProfileInfo=False,
                     SliccyEnableUpdater=release)
        path.write_bytes(plistlib.dumps(plist, sort_keys=False))
