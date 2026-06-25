# UploadProbe

A command-line tool for generating test files with embedded payloads to audit file upload endpoints during security assessments and bug bounty hunting.

## Features

- Generate test files in 10 formats: CSV, JPEG, PNG, GIF, WebP, PDF, SVG, TIFF, BMP, ICO, EICAR
- Embed payloads directly into file metadata and binary structures
- Built-in payload presets for common vulnerability classes
- Multiple presets in one command
- Batch generation across all formats in one command
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
```

## Options

| Flag              | Description                                               |
| ----------------- | --------------------------------------------------------- |
| `file_path`       | Output path — extension determines format                 |
| `-t`, `--text`    | Text rendered inside image or PDF                         |
| `-p`, `--payload` | Raw payload to embed in file structure                    |
| `-b`, `--bytes`   | Target file size e.g. `10KB`, `5MB` (PNG only)            |
| `--preset`        | One or more built-in presets e.g. `--preset xss ssrf xxe` |
| `--list-presets`  | Show all available presets                                |
| `--all BASENAME`  | Generate all formats at once                              |

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

## What to Test

- Does the server strip or sanitize file metadata?
- Does the application reflect metadata back anywhere (stored XSS)?
- Does the server parse CSV without sanitizing formula characters?
- Does the WAF/AV block EICAR?
- Does the endpoint enforce file size limits?
- Does the server accept all MIME types or just specific ones?
- Does the server render SVG directly in the browser?

## Legal

This tool is intended for authorized security testing only. Only use it against systems you own or have explicit written permission to test. The author is not responsible for misuse.

## Credits

This tool is inspired by and built upon the original work of:

- [sterrasec/dummy](https://github.com/sterrasec/dummy)
