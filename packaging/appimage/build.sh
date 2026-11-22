#!/bin/sh
# Builds a portable 67zip AppImage: target/appimage/67zip-<arch>.AppImage
#
# Needs network once: it downloads appimagetool from the AppImage project's
# GitHub releases and runs it. Review that before running this script.
#
# The binaries only need glibc; display, keyboard and GPU libraries are
# loaded from the user's system at run time. An AppImage runs on distros
# with the same or a newer glibc than the build machine, so build releases
# on an old distro (for example Ubuntu 22.04, glibc 2.35).
set -eu
cd "$(dirname "$0")/../.."
APP=io.github.gamesensicals.SixtySevenZip
ARCH="$(uname -m)"
OUT=target/appimage
DIR="$OUT/AppDir"

cargo build --release --locked -p zip67-cli -p zip67-gui

rm -rf "$DIR"
install -Dm755 target/release/67zip "$DIR/usr/bin/67zip"
install -Dm755 target/release/67z "$DIR/usr/bin/67z"
install -Dm644 "data/$APP.desktop" "$DIR/usr/share/applications/$APP.desktop"
install -Dm644 "data/$APP.metainfo.xml" "$DIR/usr/share/metainfo/$APP.appdata.xml"
install -Dm644 "data/icons/$APP.svg" "$DIR/usr/share/icons/hicolor/scalable/apps/$APP.svg"
for s in 16 32 48 64 128 256 512; do
  install -Dm644 "data/icons/$APP-$s.png" "$DIR/usr/share/icons/hicolor/${s}x${s}/apps/$APP.png"
done
cp "data/$APP.desktop" "$DIR/$APP.desktop"
cp "data/icons/$APP-256.png" "$DIR/$APP.png"
cp "data/icons/$APP-256.png" "$DIR/.DirIcon"
cat > "$DIR/AppRun" <<'RUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
# Started as "67z" (e.g. through a symlink): run the command line tool.
case "$(basename "${ARGV0:-$0}")" in
  67z|67z.*) exec "$HERE/usr/bin/67z" "$@" ;;
esac
exec "$HERE/usr/bin/67zip" "$@"
RUN
chmod 755 "$DIR/AppRun"

TOOL="$OUT/appimagetool-$ARCH.AppImage"
if [ ! -x "$TOOL" ]; then
  curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$ARCH.AppImage"
  chmod +x "$TOOL"
fi
# APPIMAGE_EXTRACT_AND_RUN lets the tool run without FUSE (containers, CI).
APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$ARCH" "$TOOL" --no-appstream "$DIR" "$OUT/67zip-$ARCH.AppImage"
echo "Built $OUT/67zip-$ARCH.AppImage"
