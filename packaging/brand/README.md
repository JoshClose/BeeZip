# BeeZip's brand marks

The sources the app's icons and in-app art are made from. Colours are the app's own palette
(`apps/desktop/src/index.css`): amber `#E0A21A`, deep amber `#9A6700`, ink `#1F2023`, cream
`#FBEFCF`, white.

| File | What it is | Where it goes |
|---|---|---|
| `logo.svg` | The logo: a top-down bee in an amber-outlined comb cell. | The installer, About, the README. |
| `app-icon.svg` | The logo with its cell filled white, so the ink bee reads on a dark taskbar. | Every app icon from 24 px up. |
| `app-icon-16.svg` | The bee alone, cropped to fill the square, with a white edge for dark taskbars. | The 16 px image in `icon.ico`. |
| `comb-lifted.svg` | Seven comb cells, one lifted out of the rosette: a file leaving the archive. | The job window while it extracts (the cell comes out, again and again, and rests out), and the website. |
| `comb-placing.svg` | The same comb, the ink cell going back into its outlined place: a file going into an archive. | The job window while it compresses or adds (the cell goes in, and rests in), and the website. |
| `comb-rosette.svg` | Seven comb cells, amber and deep amber around an ink centre. | The job window while it tests (the cells glow in turn), and the website's loading mark and footer. |

Each is drawn on a 120 × 120 grid with no background, except `app-icon-16.svg`, which crops to
the bee's 88 × 88. The app draws the three combs itself, from the same cells
(`apps/desktop/src/components/CombMark.tsx`, moving in `index.css`), so a change here goes there
too.

## The app's icons

`apps/desktop/src-tauri/icons` is made from `app-icon.svg` and `app-icon-16.svg`, never edited by
hand:

```powershell
pnpm --dir apps/desktop install    # once: Tauri's CLI renders the SVGs
cargo xtask icons                  # rewrites the icons; commit them with the SVG change
```

At 16 px the cell's outline would take the edge pixels and leave the bee about 7 px wide, so
`icon.ico`'s 16 px image is the bee alone. CI runs `cargo xtask icons --check`, which fails when
the committed icons don't match the SVGs.
