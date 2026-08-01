# UploadProbe

A command-line tool for generating test files with embedded payloads to audit file upload endpoints during security assessments and bug bounty hunting.

## Features

- Generate test files in 10 formats: CSV, JPEG, PNG, GIF, WebP, PDF, SVG, TIFF, BMP, ICO, EICAR
- Embed payloads directly into file metadata and binary structures
- Built-in payload presets for common vulnerability classes
- Multiple presets in one command
- Batch generation across all formats in one command
- CSPT JSON polyglot generation for bypassing file-type upload validators
- Built-in self-check verification for generated polyglots
- Automatic system font detection (no manual font setup)
- Size padding for testing upload size limits

## Installation

```bash
git clone https://github.com/bytewreaker/UploadProbe
cd UploadProbe
pip install -r requirements.txt
python uploadprobe.py --help
```

## Requirements

```bash
pip install Pillow reportlab rich
```

## Usage

```bash
# Generate a basic JPEG
python uploadprobe.py test.jpeg

# Embed a custom payload
python uploadprobe.py test.png -p '<svg onload=alert(1)>'

# Use a built-in preset
python uploadprobe.py test.svg --preset xss

# Use multiple presets at once
python uploadprobe.py --all output --preset xss ssrf xxe

# Generate all formats at once
python uploadprobe.py --all test_upload --preset formula

# Size-padded PNG
python uploadprobe.py big.png -b 5MB

# EICAR antivirus test file
python uploadprobe.py eicar_test.txt

# List all presets
python uploadprobe.py --list-presets

# Generate a CSPT JSON polyglot targeting a specific validator
python uploadprobe.py --cspt webp --cspt-path "../../../../CSPT?"

# Generate all CSPT polyglot variants at once, self-checked
python uploadprobe.py --cspt all --cspt-path "../CSPT_PAYLOAD"

# List CSPT techniques
python uploadprobe.py --list-cspt
```

## Options

| Flag              | Description                                                                         |
| ----------------- | ----------------------------------------------------------------------------------- |
| `file_path`       | Output path — extension determines format                                           |
| `-t`, `--text`    | Text rendered inside image or PDF                                                   |
| `-p`, `--payload` | Raw payload to embed in file structure                                              |
| `-b`, `--bytes`   | Target file size e.g. `10KB`, `5MB` (PNG/CSV only)                                  |
| `--preset`        | One or more built-in presets e.g. `--preset xss ssrf xxe`                           |
| `--list-presets`  | Show all available presets                                                          |
| `--all BASENAME`  | Generate all formats at once                                                        |
| `--cspt`          | Generate a CSPT JSON polyglot: `mmmagic`, `pdflib`, `filecmd`, `webp`, or `all`     |
| `--cspt-path`     | Traversal string embedded as the JSON gadget payload (default: `../../../../CSPT?`) |
| `--list-cspt`     | Show all CSPT polyglot techniques                                                   |
| `--no-verify`     | Skip self-check verification after generating CSPT polyglots                        |

## Supported Formats & Payload Injection Points

| Format | Injection Point                    |
| ------ | ---------------------------------- |
| JPEG   | Comment segment (`0xFFFE`)         |
| PNG    | `tEXt` chunk (before `IEND`)       |
| GIF    | Comment Extension (`0x21 0xFE`)    |
| WebP   | XMP metadata                       |
| PDF    | Hidden white-on-white text layer   |
| SVG    | Raw XML tag inside `<svg>`         |
| TIFF   | EXIF `ImageDescription` tag (270)  |
| BMP    | Reserved header bytes (offset 6–9) |
| ICO    | Appended after binary              |
| CSV    | Header cell (formula injection)    |
| EICAR  | AV test string                     |

## Built-in Presets

| Name       | Payload Type                   | Best Format                |
| ---------- | ------------------------------ | -------------------------- |
| `xss`      | Stored XSS via metadata        | JPEG, PNG, GIF, WebP, TIFF |
| `xss2`     | SVG-based XSS                  | SVG                        |
| `xss-svg`  | Script tag XSS                 | SVG                        |
| `sqli`     | SQL injection probe            | CSV, PDF                   |
| `formula`  | CSV formula injection          | CSV                        |
| `lfi`      | Local file inclusion path      | Any                        |
| `ssti`     | Server-side template injection | Any                        |
| `xxe`      | XML external entity            | SVG, PDF                   |
| `polyglot` | Multi-context script tag       | Any                        |
| `ssrf`     | AWS metadata SSRF via SVG      | SVG                        |

## CSPT JSON Polyglots

Generates files that are simultaneously valid JSON (parseable client-side via `JSON.parse`) _and_ accepted by a specific server-side file-type validator, for testing Client-Side Path Traversal (CSPT) gadget-upload flows behind upload restrictions.

| Technique | Bypasses                                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `mmmagic` | Node.js mmmagic MIME sniffing — `%PDF` magic bytes anywhere in first 1024 bytes                                                 |
| `pdflib`  | pdf-lib structural PDF validation — minimal valid PDF object graph embedded as a JSON string value                              |
| `filecmd` | `file` command / libmagic CLI — pads past the default 1MB read limit so JSON-parse detection falls back to magic-byte detection |
| `webp`    | file-type-style libraries (e.g. `sindresorhus/file-type`) — places `WEBP` at the fixed byte offset the library checks           |

Each generated file is automatically re-parsed with `json.loads` and checked against the structural property its technique depends on (magic-byte window, fixed offset, or padded size), with pass/fail results printed in a table. Use `--no-verify` to skip this.

Based on the technique described in Doyensec's ["Bypassing File Upload Restrictions To Exploit Client-Side Path Traversal"](https://blog.doyensec.com/) (Jan 2025).

## What to Test

- Does the server strip or sanitize file metadata?
- Does the application reflect metadata back anywhere (stored XSS)?
- Does the server parse CSV without sanitizing formula characters?
- Does the WAF/AV block EICAR?
- Does the endpoint enforce file size limits?
- Does the server accept all MIME types or just specific ones?
- Does the server render SVG directly in the browser?
- Does the server validate uploaded files using only a partial signal (magic bytes, fixed offset, size threshold) rather than fully verifying the format — and can that gap be used to smuggle a JSON gadget for CSPT?

## Legal

This tool is intended for authorized security testing only. Only use it against systems you own or have explicit written permission to test. The author is not responsible for misuse.

## Credits

This tool is inspired by and built upon the original work of:

- [sterrasec/dummy](https://github.com/sterrasec/dummy)
- CSPT polyglot techniques based on Doyensec's research: [blog.doyensec.com](https://blog.doyensec.com/)
