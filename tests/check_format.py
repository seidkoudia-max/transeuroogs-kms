"""Check formatting with the gofmt belonging to the selected Go toolchain."""
import pathlib
import subprocess
import sys

root = subprocess.check_output([sys.argv[1], "env", "GOROOT"], text=True).strip()
result = subprocess.run([str(pathlib.Path(root) / "bin/gofmt"), "-l", "src"], capture_output=True, text=True, check=True)
if result.stdout:
    print("Run gofmt on:\n" + result.stdout)
    sys.exit(1)
