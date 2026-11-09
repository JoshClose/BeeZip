# The rpm's %postun: Tauri's rpm owns the files it's given but not their folders, so erasing
# BeeZip would leave /usr/share/doc/beezip behind, empty. $1 is 0 when BeeZip is erased, 1 on an
# upgrade (when the new version's notices are already there).
if [ "$1" = 0 ]; then
  rmdir /usr/share/doc/beezip 2> /dev/null
fi
exit 0
