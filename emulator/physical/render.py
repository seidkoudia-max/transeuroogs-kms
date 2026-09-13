"""Render a self-contained, key-free, interactive emulation report."""
import argparse
import json
from pathlib import Path


def render(report_path, output, acceptance=None):
    report = json.loads(Path(report_path).read_text())
    if acceptance:
        report['runtime_acceptance'] = json.loads(Path(acceptance).read_text())
    template = Path(__file__).with_name('report-template.html').read_text()
    # JSON data is inert script content; escape HTML terminators.
    data = json.dumps(report, allow_nan=False).replace('<', '\\u003c').replace('&', '\\u0026')
    Path(output).write_text(template.replace('<!--REPORT_JSON-->', data))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--acceptance', type=Path)
    args = parser.parse_args(); render(args.report, args.out, args.acceptance)
