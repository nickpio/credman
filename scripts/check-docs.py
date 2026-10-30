#!/usr/bin/env python3
"""Check repository Markdown links without accessing external services."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


def check_links(root):
    failures = []
    documents = [root / 'README.md', root / 'SECURITY.md', *sorted((root / 'docs').rglob('*.md'))]
    for document in documents:
        text = document.read_text()
        for match in re.finditer(r'\]\(([^\s)]+)\)', text):
            target = match.group(1).strip('<>')
            link = urlsplit(target)
            if link.scheme or link.netloc:
                continue
            destination = document.parent / unquote(link.path) if link.path else document
            line = text.count('\n', 0, match.start()) + 1
            if not destination.exists():
                failures.append(f'{document.relative_to(root)}:{line}: missing target {target}')
            elif link.fragment and destination.suffix == '.md':
                headings = re.findall(r'^#{1,6}\s+(.+?)\s*#*$', destination.read_text(), re.MULTILINE)
                anchors = {re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-') for heading in headings}
                if unquote(link.fragment) not in anchors:
                    failures.append(f'{document.relative_to(root)}:{line}: missing heading {target}')
    return documents, failures


def main():
    documents, failures = check_links(ROOT)
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Checked local links and headings in {len(documents)} Markdown documents.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
