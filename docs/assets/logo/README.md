# NOS logo

The mark is a carrier pigeon whose body is a nitrous-oxide bottle: it delivers
packets (the bottle's label is a packet-header diagram), and it delivers them
fast (NOS). The wordmark is a slanted block face with two speed slits, like a
racing decal.

## Files

| File | Use |
|------|-----|
| `nos-horizontal.svg` / `-dark.svg` | Default lockup: README, website header, slides |
| `nos-stacked.svg` / `-dark.svg` | Square-ish spaces: posters, stickers, title slides |
| `nos-mark.svg` / `-dark.svg` | The pigeon alone, 48 px and up |
| `nos-mark-small.svg` / `-dark.svg` | The pigeon below 48 px (no eyes, no header grid, smooth wings) |
| `nos-wordmark.svg` / `-dark.svg` | The name alone, when the mark already appears nearby |
| `nos-mark-{black,white,orange}.svg`, `nos-horizontal-{black,white}.svg` | One-colour: print, engraving, stamps, embroidery |
| `nos-app-icon.svg`, `nos-maskable.svg` | Rounded and full-bleed (Android maskable) icon tiles |
| `web/` | `favicon.ico`/`.svg`, PNG favicons, touch/PWA icons, `site.webmanifest` |
| `social-preview.png` | GitHub repository image (1280×640): Settings → General → Social preview |

`-dark` means *for dark backgrounds*: lighter wings and head, light lettering.

## Colours

| Role | HEX | RGB |
|------|-----|-----|
| Nitro orange (bottle, brand colour) | `#E8531F` | 232 83 31 |
| Ink (wings, lettering, icon tile) | `#2A2D3A` | 42 45 58 |
| Neck purple | `#7B5CFF` | 123 92 255 |
| Flame yellow (flame, beak) | `#FFC23D` | 255 194 61 |
| Pigeon grey (head, nozzle) | `#A3A9B8` | 163 169 184 |
| Dark-mode wings / head | `#6E7488` / `#C2C7D3` | |
| Paper (lettering on dark) | `#F2F2F2` | 242 242 242 |

When only one colour is available, use nitro orange, ink, black or white —
never the purple or yellow alone.

## Rules

- **Clear space:** keep at least the height of the pigeon's head (about 1/3 of
  the mark's height) empty on every side.
- **Minimum size:** horizontal lockup 120 px wide (24 mm in print); mark 48 px,
  below that switch to `nos-mark-small.svg` (works down to 16 px).
- **Backgrounds:** the colour versions on white or very light backgrounds, the
  `-dark` versions on ink or darker; on photos or mid-tones use a one-colour version.
- **Don't** recolour individual parts, rotate the mark (the 45° climb is the
  idea), straighten or re-space the lettering, close the speed slits, add
  shadows or outlines, or set "NOS" in another typeface next to the mark.

The lettering is drawn as paths, not a font: there is no typeface to install
or license.
