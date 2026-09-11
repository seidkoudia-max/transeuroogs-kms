"""Launch an isolated PostgreSQL cluster and run operational acceptance.

The server listens only on a private Unix socket. No persistent user database or
real credentials are accessed. PostgreSQL binaries must already be installed.
"""
import argparse
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--pg-bin", default=os.environ.get("KMS_PG_BIN"))
    args = parser.parse_args()
    if not args.pg_bin:
        args.pg_bin = subprocess.check_output(["pg_config", "--bindir"], text=True).strip()
    pg = pathlib.Path(args.pg_bin)
    with tempfile.TemporaryDirectory(prefix="kms-ops-") as tmp:
        root = pathlib.Path(tmp)
        data, sockets, logfile = root / "database", root / "socket", root / "postgres.log"
        sockets.mkdir(mode=0o700)
        env = dict(os.environ, LC_ALL="C", LANG="C")
        started = False
        with logfile.open("w") as log:
            try:
                subprocess.run([pg / "initdb", "-D", data, "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8", "--locale=C"],
                               check=True, stdout=log, stderr=log, env=env)
                subprocess.run([pg / "pg_ctl", "-D", data, "-l", str(root / "server.log"), "-o",
                                "-h '' -k " + str(sockets) + " -p 55436", "start"], check=True, stdout=log, stderr=log, env=env)
                started = True
                env["KMS_TEST_DSN"] = "host=" + str(sockets) + " port=55436 dbname=postgres sslmode=disable"
                dsn = root / "dsn"; dsn.write_text(env["KMS_TEST_DSN"]); dsn.chmod(0o600)
                subprocess.run([args.go, "test", "-race", "./src/internal/postgres"], cwd=ROOT, env=env, check=True)
                for name in ("kms", "eagle-emulator", "test-pki"):
                    subprocess.run([args.go, "build", "-o", str(root / name), "./src/cmd/" + name], cwd=ROOT, env=env, check=True)
                subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "src/application", "-p", "test_*.py"], cwd=ROOT, env=env, check=True)
                subprocess.run([sys.executable, "emulator/operational/demo.py", "--binary", root / "kms", "--emulator", root / "eagle-emulator",
                                "--pki", root / "test-pki", "--dsn-file", dsn], cwd=ROOT, env=env, check=True)
            finally:
                if started:
                    subprocess.run([pg / "pg_ctl", "-D", data, "-m", "fast", "stop"], stdout=log, stderr=log, env=env, timeout=15)


if __name__ == "__main__":
    main()
