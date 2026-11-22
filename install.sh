#!/bin/sh
# Builds and installs 67zip for the current user (~/.local) or, with
# --system, for everybody (/usr/local, needs root).
#   ./install.sh            build + install for this user
#   ./install.sh --system   install system-wide (run as root after building
#                           as your user; root never compiles)
#   ./install.sh --uninstall [--system]
set -eu
cd "$(dirname "$0")"
APP=io.github.gamesensicals.SixtySevenZip
PREFIX="$HOME/.local"
UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --system) PREFIX=/usr/local ;;
    --uninstall) UNINSTALL=1 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done
BIN="$PREFIX/bin"; SHARE="$PREFIX/share"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
[ "$PREFIX" = /usr/local ] && DATA_HOME="$SHARE"

files() {
  echo "$BIN/67zip"; echo "$BIN/67z"
  echo "$SHARE/applications/$APP.desktop"
  echo "$SHARE/metainfo/$APP.metainfo.xml"
  echo "$SHARE/icons/hicolor/scalable/apps/$APP.svg"
  for s in 16 32 48 64 128 256 512; do echo "$SHARE/icons/hicolor/${s}x${s}/apps/$APP.png"; done
  echo "$DATA_HOME/kio/servicemenus/67zip-servicemenu.desktop"
  echo "$DATA_HOME/kio/servicemenus/67zip-extract-servicemenu.desktop"
  echo "$DATA_HOME/nemo/actions/67zip-extract-here.nemo_action"
  echo "$DATA_HOME/nemo/actions/67zip-add.nemo_action"
  echo "$DATA_HOME/nemo/actions/67zip-add-password.nemo_action"
  echo "$DATA_HOME/nautilus/scripts/67zip - Add to archive"
  echo "$DATA_HOME/nautilus/scripts/67zip - Compress to zip with a password"
  echo "$DATA_HOME/nautilus/scripts/67zip - Extract here"
}

if [ "$UNINSTALL" = 1 ]; then
  files | while read -r f; do rm -f "$f"; done
  echo "67zip removed from $PREFIX"
  exit 0
fi

if [ "$(id -u)" = 0 ]; then
  # Never compile as root: building runs code from every dependency.
  if [ ! -x target/release/67zip ] || [ ! -x target/release/67z ]; then
    echo "Build 67zip as your normal user first (./install.sh, or: cargo build --release --locked -p zip67-cli -p zip67-gui),"
    echo "then run 'sudo ./install.sh --system' to install the built programs."
    exit 1
  fi
else
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust is needed to build 67zip: https://rustup.rs"; exit 1
  fi
  cargo build --release --locked -p zip67-cli -p zip67-gui
fi

install -Dm755 target/release/67zip "$BIN/67zip"
install -Dm755 target/release/67z "$BIN/67z"
install -Dm644 "data/$APP.desktop" "$SHARE/applications/$APP.desktop"
install -Dm644 "data/$APP.metainfo.xml" "$SHARE/metainfo/$APP.metainfo.xml"
install -Dm644 "data/icons/$APP.svg" "$SHARE/icons/hicolor/scalable/apps/$APP.svg"
for s in 16 32 48 64 128 256 512; do
  install -Dm644 "data/icons/$APP-$s.png" "$SHARE/icons/hicolor/${s}x${s}/apps/$APP.png"
done
# File manager menus: Dolphin (KDE), Nemo (Cinnamon), Nautilus (GNOME).
install -Dm644 data/kio/67zip-servicemenu.desktop "$DATA_HOME/kio/servicemenus/67zip-servicemenu.desktop"
install -Dm644 data/kio/67zip-extract-servicemenu.desktop "$DATA_HOME/kio/servicemenus/67zip-extract-servicemenu.desktop"
chmod +x "$DATA_HOME/kio/servicemenus/"67zip-*.desktop 2>/dev/null || true
install -Dm644 data/nemo/67zip-extract-here.nemo_action "$DATA_HOME/nemo/actions/67zip-extract-here.nemo_action"
install -Dm644 data/nemo/67zip-add.nemo_action "$DATA_HOME/nemo/actions/67zip-add.nemo_action"
install -Dm644 data/nemo/67zip-add-password.nemo_action "$DATA_HOME/nemo/actions/67zip-add-password.nemo_action"
install -Dm755 data/nautilus/67zip-add.sh "$DATA_HOME/nautilus/scripts/67zip - Add to archive"
install -Dm755 data/nautilus/67zip-add-password.sh "$DATA_HOME/nautilus/scripts/67zip - Compress to zip with a password"
install -Dm755 data/nautilus/67zip-extract-here.sh "$DATA_HOME/nautilus/scripts/67zip - Extract here"

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$SHARE/applications" || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t "$SHARE/icons/hicolor" || true

case ":$PATH:" in *":$BIN:"*) ;; *) echo "Note: add $BIN to your PATH to run 67z from a terminal." ;; esac
echo "67zip installed to $PREFIX. Start it from your applications menu or run: 67zip"
