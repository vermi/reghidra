#!/bin/bash
set -euo pipefail

# Build a macOS .app bundle for Reghidra
# Usage: ./scripts/bundle-macos.sh [--debug]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="debug"
fi

APP_NAME="Reghidra"
BUNDLE_DIR="$PROJECT_ROOT/target/$APP_NAME.app"
CONTENTS="$BUNDLE_DIR/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES_DIR="$CONTENTS/Resources"

VERSION=$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
VERSION="${VERSION:-0.1.0}"

echo "Building reghidra ($PROFILE)..."
if [[ "$PROFILE" == "release" ]]; then
    cargo build --release --package reghidra-gui
    BINARY="$PROJECT_ROOT/target/release/reghidra"
else
    cargo build --package reghidra-gui
    BINARY="$PROJECT_ROOT/target/debug/reghidra"
fi

echo "Creating app bundle at $BUNDLE_DIR..."
rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Copy binary
cp "$BINARY" "$MACOS_DIR/reghidra"

# Generate Info.plist
cat > "$CONTENTS/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>com.reghidra.app</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>reghidra</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key>
            <string>Binary File</string>
            <key>CFBundleTypeRole</key>
            <string>Viewer</string>
            <key>LSItemContentTypes</key>
            <array>
                <string>public.executable</string>
                <string>public.data</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
PLIST

# Ad-hoc code sign (required by macOS to launch .app bundles)
echo "Code signing..."
codesign --force --deep --sign - "$BUNDLE_DIR"

echo ""
echo "Done! App bundle created at:"
echo "  $BUNDLE_DIR"
echo ""
echo "To run:  open \"$BUNDLE_DIR\""
echo "To install: cp -r \"$BUNDLE_DIR\" /Applications/"
