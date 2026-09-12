"""Prepare an explicitly supplied, clean TeraFlow v7 checkout for our driver.

This edits source only; it never contacts a cluster or embeds credentials.
"""
import argparse
import pathlib
import shutil
import subprocess

PIN = "fb8707871eba26806cac7ac373c70b2bb5bd26fc"
ROOT = pathlib.Path(__file__).resolve().parents[2]


def prepare(checkout):
    checkout = checkout.resolve()
    head = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        raise RuntimeError("Requires pinned TeraFlow v7.0.0 checkout")
    registration = checkout / "src/device/service/drivers/__init__.py"
    original = registration.read_text()
    old = "from .qkd.QKDDriver2 import QKDDriver"
    new = "from .transeuroogs.Selector import QKDDriver"
    target = registration.parent / "transeuroogs"
    if new in original and target.exists():
        raise RuntimeError("Already prepared; review changes before refreshing")
    if original.count(old) != 1 or target.exists():
        raise RuntimeError("Unexpected driver layout; refusing overwrite")
    status = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True)
    if status.strip():
        raise RuntimeError("Use a clean checkout to preserve existing work")
    shutil.copytree(ROOT / "src/sdn/teraflow", target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    registration.write_text(original.replace(old, new))
    print("Prepared TeraFlow v7 driver extension; no cluster changes made.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=pathlib.Path)
    prepare(parser.parse_args().checkout)
