#!/usr/bin/env python3
"""Install Nikto's pure-Perl XML writer into the workspace, without sudo."""
import argparse
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path

URL = "https://cpan.metacpan.org/authors/id/J/JO/JOSEPHW/XML-Writer-0.900.tar.gz"
SHA256 = "73c8f5bd3ecf2b350f4adae6d6676d52e08ecc2d7df4a9f089fa68360d400d1f"
ROOT = Path(__file__).resolve().parent.parent


def install(payload):
    if hashlib.sha256(payload).hexdigest() != SHA256:
        raise ValueError("XML::Writer download failed its SHA-256 check.")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for source, destination in (("Writer.pm", "lib/perl5/XML/Writer.pm"),
                                    ("LICENSE", "share/XML-Writer-LICENSE")):
            target = ROOT / "tools/perl5" / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile("XML-Writer-0.900/" + source).read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Use an already downloaded archive (still checksum verified).")
    args = parser.parse_args()
    if args.archive:
        data = args.archive.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(1_000_001)
    install(data)
    print("Installed XML::Writer 0.900 into tools/perl5.")
