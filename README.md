# Satori

A quiet Nostr client for the Linux desktop: native Rust on GPUI (the
Zed toolkit), one window, a minimalist ink-and-paper visual style.

Satori is built on three commitments:

- **Your keys stay yours.** The app never sees your master private key:
  you sign in through a remote signer (`bunker://` or `nostrconnect://`,
  NIP-46) and every incoming event is verified locally; relays are
  treated as untrusted. No telemetry. Privacy modes gate media today;
  the Tor transport itself is still pending (DESIGN.md M5), so traffic
  runs direct until it lands.
- **The event stream is the state.** Everything on screen is a projection
  of your Nostr events. New event kinds are supported through a handler
  registry (`KindHandler`), not hardcoded into the views.
- **Quiet by default.** Every publish passes through a restart-safe undo
  window, so a stray post can be recalled. No like or repost counters,
  notifications only for what matters, and a restrained visual design:
  whitespace over boxes, one accent color used sparingly.

## Status

Satori is a daily-driver desktop client, in active development.

- Timeline: endless scrolling through your history. Media, quotes,
  reposts (NIP-18), polls (NIP-88, vote and compose), long-form articles
  (NIP-23), hashtag timelines; a pill counts new notes that arrive
  while you read and loads them on click; link preview cards (the
  page's og: metadata) with tracking parameters stripped from every
  link in every note
- Threads: NIP-10 reply trees, NIP-22 comments (on articles too, with
  reply affordance and counts), reply-to-root routing
- Composer: tabs for note, picture (NIP-68), video (NIP-71 kind 22),
  poll, and article; an undo window on every publish kind, draft restore,
  scheduled posts, Blossom attachments, @-mentions, quote cards
- Zaps: NIP-57 with verified receipts, paid through a connected NWC
  wallet (NIP-47); wallet and bunker URIs are screened at paste time
  (private-address relays ask first, consents revocable in settings)
- Notifications: replies, comments, zaps, poll votes; reactions behind a pref;
  an accurate tally strip scoped by a timeframe dropdown (24h/7d/30d)
- Profiles: banner and avatar header, NIP-05 verification badge,
  click-to-copy npub and Lightning address, notes rendered exactly as
  the timeline renders them, endless photos/videos media strips
- Inline video: poster tiles, click-to-play, one GStreamer player per process
- Search (NIP-50), list backup (export/import), NIP-78 preference sync,
  light and dark themes, reduced-motion honored

Not done yet: NIP-37 draft sync, a debug metrics pane, the private-relay
routing policy, and Tor-routed traffic (the M5 transport). Flatpak
packaging exists: tag-driven deb/rpm/flatpak builds (`.github/workflows/
release.yml`), with local installs via `packaging/install-local.sh`
(binary, desktop file, and icons into `~/.local`). The full design and
build spec is [DESIGN.md](DESIGN.md).

## Development

On hosts without GTK/Vulkan development headers (immutable desktops like
bootc or Silverblue), builds run in a container; the cargo cache lives in
a named volume, so tooling stays warm:

    podman build -t satori-dev -f Containerfile.dev
    podman run --rm -v satori-cargo:/usr/local/cargo -v "$PWD:/srv:Z" -w /srv satori-dev cargo check --workspace
    podman run --rm -v satori-cargo:/usr/local/cargo -v "$PWD:/srv:Z" -w /srv satori-dev cargo clippy --workspace
    podman run --rm -v satori-cargo:/usr/local/cargo -v "$PWD:/srv:Z" -w /srv satori-dev cargo test -p satori-core

Run it on the host. GPUI needs `libxkbcommon-x11`:

    cargo build -p satori-gpui
    LD_LIBRARY_PATH=~/.local/lib ./target/debug/satori-desktop

Layout: `crates/core` is the Nostr domain layer (no UI dependency);
`crates/app-gpui` is the binary it feeds. `AGENTS.md` covers conventions and
gates. The original TypeScript web app was retired when the Rust port
reached feature parity; its final state lives in git history at commit
`a4b09e8` (`git show a4b09e8:src/<file>`).

## License

[MIT](LICENSE) © 2026 Letdown2491
