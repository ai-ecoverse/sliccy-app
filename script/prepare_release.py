#!/usr/bin/env python3
"""Validate the production bundle, sign its ZIP, and generate the GitHub appcast."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import xml.etree.ElementTree as ET
from release_metadata import ROOT, configuration
import user_notes

SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ET.register_namespace("sparkle", SPARKLE)

def make_appcast(config, name, size, signature, history):
    if len(base64.b64decode(signature, validate=True)) != 64 or size <= 0:
        raise ValueError("invalid archive signature or length")
    history = [user_notes.entry(**item) for item in history]
    if not history or history[0]["version"] != config["version"] or history[0]["build"] != config["build"]:
        raise ValueError("update notes do not describe this release")
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "Sliccy updates"
    item = ET.SubElement(channel, "item")
    ET.SubElement(item, "title").text = "Sliccy " + config["version"]
    ET.SubElement(item, f"{{{SPARKLE}}}version").text = config["build"]
    ET.SubElement(item, f"{{{SPARKLE}}}shortVersionString").text = config["version"]
    ET.SubElement(item, f"{{{SPARKLE}}}minimumSystemVersion").text = config["minimumSystemVersion"]
    ET.SubElement(item, f"{{{SPARKLE}}}hardwareRequirements").text = "arm64"
    ET.SubElement(item, "link").text = f'https://github.com/ai-ecoverse/sliccy-app/releases/tag/v{config["version"]}'
    ET.SubElement(item, f"{{{SPARKLE}}}fullReleaseNotesLink").text = "https://github.com/ai-ecoverse/sliccy-app/releases"
    # HTML with escaped notes; Sparkle's WebView runs no page JavaScript.
    ET.SubElement(item, "description").text = user_notes.render_html(history)
    # Structured copy the next release reads back to extend the history.
    item.append(user_notes.history_element(history))
    ET.SubElement(item, "enclosure", {
        "url": f'https://github.com/ai-ecoverse/sliccy-app/releases/download/v{config["version"]}/{name}',
        "length": str(size), "type": "application/octet-stream",
        f"{{{SPARKLE}}}edSignature": signature,
    })
    return ET.tostring(rss, encoding="utf-8", xml_declaration=True)

def prepare(directory):
    config = configuration()
    app = directory / "Sliccy.app"
    plist = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    expected = {"CFBundleIdentifier": "ai.sliccy.mac", "CFBundleShortVersionString": config["version"],
                "CFBundleVersion": config["build"], "SUFeedURL": config["feedURL"],
                "SUPublicEDKey": config["publicEDKey"], "LSMinimumSystemVersion": config["minimumSystemVersion"],
                "SliccyEnableUpdater": True, "SUAllowsAutomaticUpdates": False}
    for key, value in expected.items():
        if plist.get(key) != value:
            raise ValueError(f"bundle-release-mismatch: {key}")
    if (app / "Contents/Helpers").exists():
        raise ValueError("proof helpers in release")
    if 'static let identityProofApproved = false' not in (ROOT / "Sources/Sliccy/Screen/ScreenPeerVerifier.swift").read_text():
        raise ValueError("capture release policy changed")
    for name in ["Contents/Frameworks/Sparkle.framework/Sparkle", "Contents/Resources/AppIcon.icns", "Contents/Resources/slicc"]:
        if not (app / name).is_file():
            raise ValueError(f"missing bundle resource: {name}")
    arch = subprocess.check_output(["/usr/bin/lipo", "-archs", str(app / "Contents/MacOS/Sliccy")], text=True).strip()
    if arch != "arm64":
        raise ValueError("release architecture must be arm64")
    archive = directory / f'Sliccy-{config["version"]}.zip'
    tools = ROOT / ".build/local-app/artifacts/sparkle/Sparkle/bin"
    secret = os.environ.pop("SPARKLE_PRIVATE_KEY")
    signature = subprocess.check_output([str(tools / "sign_update"), "--ed-key-file", "-", "-p", str(archive)], input=secret, text=True).strip()
    del secret
    subprocess.run(["/usr/bin/xcrun", "swift", str(ROOT / "script/verify_update.swift"), config["publicEDKey"], signature, str(archive)], check=True)
    history = json.loads((ROOT / "release/update-notes.json").read_text())
    (directory / "appcast.xml").write_bytes(make_appcast(config, archive.name, archive.stat().st_size, signature, history))
    (directory / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in [archive, directory / f'Sliccy-{config["version"]}.dmg', directory / "appcast.xml"]))

if __name__ == "__main__":
    prepare(Path(sys.argv[1]).resolve())
