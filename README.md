```markdown
# nfoslide.sh

A secure, terminal-based slideshow of random NFO and ANSI art from the [16colo.rs](https://16colo.rs) artpack archive. 

`nfoslide.sh` roams decades of ANSI/ASCII art, fetching and rendering pieces directly in your terminal without ever writing to disk.

## ✨ Features

- **Zero Disk Writes**: All content lives in shell variables and pipes. Nothing is ever written to disk.
- **Secure Rendering**: Remote bytes are treated as hostile. They are interpreted onto a bounded off-screen canvas rather than sent directly to the terminal, preventing escape sequence injection (e.g., OSC 52 clipboard poisoning, terminal title spoofing).
- **True Color & iCE Colors**: Supports 24-bit VGA palette rendering and iCE bright backgrounds.
- **Dynamic Resizing**: Adjust the canvas width on the fly (`[` / `]`) if a piece looks sheared or sliced.
- **History Navigation**: Browse back and forth through the last 50 viewed artworks instantly without refetching.
- **Smart Wrapping**: Handles both DOS-style ANSI.SYS wrapping and strict VT100 wrapping.
- **No `jq` Dependency**: Parses JSON using `awk` and strict allowlists.

## 🛡️ Security & Threat Model

Writing untrusted bytes straight to a terminal is a known exploit vector. `nfoslide.sh` mitigates this by:
- **Off-screen Canvas**: Cursor motion (CUP/ED) is executed against a bounded grid and clamped. Hostile positioning can overwrite the picture, but cannot reach your shell prompt, header, or status line.
- **Sequence Filtering**: OSC, DCS, SOS, PM, APC, and charset designators are consumed and discarded outright. Only SGR (colors/styles) reaches your terminal.
- **Strict Validation**: API responses, pack names, and filenames are strictly validated against allowlists to prevent SSRF and path traversal.
- **No `--insecure`**: HTTPS is enforced, redirects are capped, and TLS verification is never bypassed.

## ⚙️ Requirements

- **Bash 4.0+** *(macOS users: `brew install bash` as the default macOS bash is 3.2)*
- **curl**
- **awk**
- **sed**
- **iconv** *(Optional, but highly recommended for CP437 to UTF-8 charset conversion)*

## 📦 Installation

```bash
git clone <repository-url>
cd <repository-directory>
chmod +x nfoslide.sh
```

## 🚀 Usage

```bash
./nfoslide.sh             # Run the slideshow
./nfoslide.sh --selftest  # Check your font, glyph widths, and colour depth
./nfoslide.sh --dump P/F  # Dump one file's bytes and metadata (for bug reports)
./nfoslide.sh --probe     # Check each API hop and show a sample, then exit
./nfoslide.sh --diagnose  # Full headers/bodies, for diagnosing 403/blocks
./nfoslide.sh --help      # Show options and keys
```

### Command Line Options

| Option | Description |
| :--- | :--- |
| `--delay SECONDS` | Seconds per line while auto-scrolling (default: `1.2`) |
| `--short MIN,MAX` | Hold time for files that fit on screen (default: `10,15`) |
| `--max-slide SECS` | Cap on any one slide; long files scroll faster to fit |
| `--width N` | Pin the canvas width (default: inferred from API per file) |
| `--no-center` | Left-align instead of centering |
| `--no-smooth` | Plain clear instead of the top-down wipe transition |
| `--no-colour` | Strip ANSI colour as well as everything else |
| `--blink` | Read SGR 5 as literal blink rather than an iCE bright background |
| `--palette vga\|term`| Draw with real VGA colours, or the terminal's own |

## ⌨️ Keyboard Controls

| Key | Action |
| :--- | :--- |
| `Space` | Pause / Resume (stays paused until pressed again) |
| `Up` / `Down` | Scroll one line |
| `PgUp` / `PgDn` | Scroll one screen |
| `Home` / `End` | Jump to start or end of the file |
| `Left` / `Right` | Previous / Next artwork (from in-memory history) |
| `[` / `]` | Canvas width -1 / +1 columns (re-rendered live) |
| `{` / `}` | Canvas width -8 / +8 columns |
| `w` | Switch line-wrap reading (DOS-style vs strict VT100) |
| `p` | Switch palette between real VGA colours and terminal's |
| `q` | Quit |
| *Any other key* | Skip to next file |

## 🔧 Environment Variables

You can override default configurations using environment variables:

- `NFO_HOST`: Content host (default: `16colo.rs`)
- `NFO_API`: API base URL (default: `https://api.16colo.rs/v1`)
- `NFO_UA`: User-Agent string. **Set this to your email if you run this often** to identify yourself to the archive operators.
- `NFO_YEAR_MIN`: Oldest year to fetch (default: `1990`)
- `NFO_FILES_PER_PACK`: Number of files to show per pack (default: `3`)
- `NFO_MAX_COLS` / `NFO_MAX_ROWS`: Canvas ceiling (default: `320x1000`)
- `NFO_SCROLL_DELAY`: Auto-scroll speed (default: `1.2`)
- `NFO_HISTORY`: Number of artworks kept in memory for history (default: `50`)
- `NFO_PALETTE`: `vga` or `term` (same as `--palette`)

## 🩺 Troubleshooting

If you encounter `403 Forbidden` errors, blank screens, or rendering issues:

1. **Diagnose Blocks**: Run `./nfoslide.sh --diagnose` to see if the block is from Cloudflare, an egress proxy, or a User-Agent rule.
2. **Identify Yourself**: If it's a User-Agent block, try setting a custom UA: 
   ```bash
   NFO_UA="nfoslide/1.2 (contact: you@example.com)" ./nfoslide.sh
   ```
3. **Check Terminal Compatibility**: Run `./nfoslide.sh --selftest` to ensure your terminal emulator correctly supports 24-bit color and single-column width for box-drawing/shade characters. (If dithering looks broken, your font or terminal width settings are likely the culprit).
4. **Inspect Specific Files**: Use `./nfoslide.sh --dump <pack>/<file>` to see the raw bytes, SAUCE metadata, and rendering structure of a specific file that isn't displaying correctly.

---
*Source: 16colo.rs artpacks (.nfo .ans .asc .txt .diz), CP437, no disk writes.*
