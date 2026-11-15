# Changelog

Releases are tagged; the CI builds the deb, rpm, apk, and flatpak from the
tag. Notes are written here first: at tagging, the new version's paragraph
becomes the `<release>` entry in
`packaging/io.github.Letdown2491.satori.metainfo.xml` (Keep this source of
truth, not the other way around).

## 0.9.0 - 2026-11-15

Video tiles earned their picture. A note's video now previews its first
frame instead of a bare box: the sniff pipeline finally reads the frame it
prerolls, big files answer a ranged head request, and files whose decode
tables live at the file's end (moov-at-end mp4s, every GIF-to-MP4
conversion) ride the same guarded range-proxy inline playback uses to pull
exactly the bytes the decoder asks for. GIF-encoded-as-mp4 clips play
inline now too: the vendored video player accepts the zero-framerate caps
those converters emit and no longer drops every frame that arrives without
a duration. The head-sniff's download cap tightened from 2MB to 1MB (files
that need more fall through to ranged fetching rather than over-fetching
blind).

Every note timestamp gained a copy button: one tap puts a `nostr:nevent1…`
(or `naddr1…` for addressable kinds) URI on the clipboard, with a short
flash to confirm the copy.

Notes with a plain link now show a preview card: the page's og: metadata
(site, title, description, thumbnail) fetched when the note scrolls into
view, capped and parsed defensively, with the thumbnail riding the ordinary
image cache. Strict Tor keeps previews off entirely. Links in note bodies
are cleaned up too: the well-known tracking params (fbclid, gclid, the
utm_* family and friends) are stripped before display, before click-through,
and before any preview fetch, so your clicks don't share their tags with
trackers.

Clicking the "new notes" chip is fast now: the notes the live feed already
saved paint immediately, and the relay round deepens in the background,
while the chip reads "Loading new notes…" until they land. In multicolumn
view the chip appears on the notes timeline only (it used to double up on
the articles column). Feeds start up faster for the same reason: page
landings no longer wait on a metadata round trip for authors the profile
cache has never seen; names and avatars patch in as they resolve. Behind
the scenes, the trust-graph's list fetch fires once per launch instead of
once per pane, and link previews load when a note scrolls into view rather
than for every note the relays push. Preview cards now appear for
extension-less web pages (a wiki slug, an App Store link used to render as
a broken picture tile that suppressed its own card), and flaky preview
fetches give up after five tries instead of retrying forever.

The disappearing-image class is closed for its remaining roots. Preview
thumbnails now come back when memory pressure drops them (they used to go
dark for the whole session once evicted), the notifications pane re-asks
for evicted images as its rows render (it only fetched at arrival before,
so anything evicted never recovered), and the relay wire pane does the
same for its rows.

The multicolumn workspace's add-column button moved from the end of the
column row (where adding a column meant scrolling the row first) into the
sidebar, above Settings. It shows while the workspace is up and the menu
it opens sits beside the rail.

## 0.8.0 - 2026-11-14

The interop pass continues on two fronts: what a note can ask for, and
where a publish goes.

Zaps learned arithmetic. A note with a zap split (NIP-57) now pays every
receiver: weights are relative, an unweighted receiver on a partially
weighted note gets nothing, a receiver with no lightning pointer fails
alone instead of failing the whole split, and a retry replays every
pending record. Zap goals (NIP-75) render as cards with live progress, a
raised-of target line, and a closed marker once the ask's deadline
passes.

Comments learned addresses. A comment on an article, picture, video or
wiki now whispers "on {name}'s note" in the notifications pane and opens
the parent by its coordinate (NIP-22): the thread fetches the
addressable anchor, learns its id, and rides from there; long-form
parents land in the reader.

The feed grew surfaces for the kinds it already carried: content
warnings veil until revealed (NIP-36), emoji shortcodes render their
images (NIP-30), subject lines headline the row (NIP-14/24), and an
unknown kind that carries an alt tag renders that description instead
of vanishing (NIP-31). Picture metadata parsing is pinned against real
client fixtures (NIP-68).

Publishing learned phase 2 of the NIP-65 routing: the app keeps
per-event seen-on memory, deletion checks ask the relays where the
original lived, profiles and relay lists publish to every known relay
so they exist where we only read, personal kinds (mute lists,
bookmarks, drafts) never broadcast, and a foreign inbox relay visits
for one publish and leaves instead of joining the pool forever.

Composing got friendlier. The emoji picker inserts the unicode
character instead of the :shortcode:; the reaction row's heart grows a
right-click quick-set (five positive glyphs plus the heart) with
tooltips; and emoji render in color at last: a vendored gpui patch
exempts the known emoji fonts from the primary-font gate, and the
composer field splits its text runs so emoji clusters ride the color
face.

Mentions learned people. The typeahead matches display name, handle,
NIP-05 and pubkey hex, and finds anyone you interact with, not just
accounts you follow; the profile mirror is seeded from the disk cache
at launch, so names resolve on the first keystroke after a restart.

The screen learned to work in columns. A rail toggle (or the c key)
opens a TweetDeck-style workspace: up to six stream columns pin side
by side, each live, each scrolling on its own; the streams are Home,
Articles, Notifications, Search, any hashtag, an author (pinned from
a profile's + Column button), or a relay (pinned from the + menu,
live only: what that relay pushes while the column is open, no
history). Drilling into a thread, article
or profile still takes the whole width, and Esc hands you back to the
columns exactly as you left them. The layout persists across
restarts: which columns, in what order, how wide. Columns reorder by
dragging their header and resize from their right edge, the rail
keeps out of the way, retiring the button of a stream already pinned,
and h/l hop the focus between columns, scrolling the target into
view. The columns never narrow: the row scrolls horizontally when
they overflow.
Two follow-up fixes from the first days with it: repost rows carry
the boosted note's action bar (the envelope used to render bare), and
the columns' add and remove buttons read at full ink.

The render riders close the interop pass's last open surfaces.
Pictures and videos with a `d` tag now show comment counts on their
action row, and clicking one opens the comment thread by its address
(NIP-22) — the thread was unreachable by id before. Voice notes render
as a row with the author's waveform and duration, and play inline
(NIP-A0): one player at a time, the same guarded door as the video
player, strict Tor degrading to the browser link. Code snippets (NIP-C0)
render in a monospace card with the file's name, language, description
and license, and a tap copies the code. A kind the app has never heard
of now renders as a quiet "unrendered kind N" line instead of
vanishing; nothing arrives invisible.

Under the hood, the interop batch got its five-lens audit (the same
performance / system usage / memory / security / duplication pass as
the previous two cycles) and the findings landed: the feed's
parent-whisper and comment-count maps are capped so a long scrolling
session cannot grow them for the process lifetime; secrets (nsec,
bunker pairing and client keys, the wallet's NWC secret) are wiped from
freed heap; the single-instance socket verifies the connecting peer's
uid and fails closed; the auth-URL door only opens http and https
links; the mention scan was moved off the per-keystroke hot path; and
the wallet pump no longer reads its own entity mid-construction at
startup. The columns batch got its own five-lens pass, and the
findings landed: a closed relay column's socket used to leak (its
pump held the subscription open after the view died; the pump now
exits with the view and the relay task unsubscribes on an idle
check), the wire column snapshots its data like the feed's instead of
deep-copying it per frame, relay URLs pass the same screening
everywhere they are typed, restored or dialed, and five hand-copied
code shapes collapsed into shared kernels, and the render-riders cycle
collapsed the fourteen publish call sites and the two schedule paths
onto shared task kernels. The riders and the refactor got the same
five-lens audit, and its findings landed: a voice row's tap on a
non-https attacker URL no longer hands the link to a desktop handler;
the comment-count fetches batch instead of firing one subscription per
picture (unbounded on the bookmarks pane); a double-tap on a voice row
can no longer spawn two players mid-build; the relay column's quote
embeds and in-flight author ledger are capped so nothing rides outside
its bounds for the session's life; and the guard sequence both players
share, the FIFO trim, and the signed-event test fixture are one kernel
each instead of hand-copies.

## 0.7.1 - 2026-11-13

The attachment-interop fix, hours after 0.7.0: a note's attached image
or video now puts its URL in the event content beside the imeta tag.
NIP-92 lets a client ignore an imeta that matches no content URL, and
the strict ones did: the attachment showed in Satori and nowhere else.
Comments get the same treatment, and an author who pastes the URL
themselves gets no duplicate. Picture and video posts were already
self-contained by design.

## 0.7.0 - 2026-11-13

The interoperability release: NIP-faithful surfaces where the client was
thin, each landed against real published-event fixtures. Comments became
a surface: kind-1111 threads render and compose on articles (the reader
grew a comments section with a reply affordance), comment counts ride
the feed bubble, and the core preserves roots and addressable targets
through nested fetches. Replies reach who they're for: publishes now
additionally target the parent author's and tagged users' inbox relays
(their kind-10002 read sets) and where the parent was recently seen, so
a reply no longer vanishes for an author who shares no relay with us.
The notifications pane gained an accurate tally strip: counts come from
the classified rows themselves, so a chip's number and its tap's row
list agree by construction, scoped by a 24h/7d/30d dropdown that
remembers its choice.

The wallet got paste-time protection (a merged outside contribution):
relays inside nostr+walletconnect:// and bunker:// URIs are screened
before any socket opens, private-address relays ask first, consents
live in the settings pane for revocation, and the wallet client is shut
down properly when a second URI replaces it. Cleartext ws:// relays are
refused outright.

Media discipline: every pane pins exactly what is on screen, so images
stop disappearing while a page idles and RAM stops ballooning on photo
profiles. The pin registry is owner-keyed with a per-owner byte cap, so
no surface can hold the whole photo budget hostage, and closing a pane
releases its pins. The reader caps comment fetches and windows their
avatars. Big pictures load now: the media path's total-request timeout
is gone in favor of connect and idle-read bounds. The flatpak now
carries the PulseAudio permission, so inline video plays its sound (the
audio socket was masked, so inline video played silently).

Under the hood: the pre-release five-lens audit (performance, system
usage, memory, security, duplication) fixed its verified findings, the
consent ledger is written atomically with 0600 permissions, preferences
sync defers to newer local edits (feed settings no longer revert at
login), the engagement engine lives in one implementation, and clicking
a user in a thread opens their profile.

## 0.6.0 - 2026-11-12

The replies-and-repairs release. Replies became surfaces, not a page: the
composer sheet opens from any action row, thread included (the full form
with attachments, alt text, preview and schedule in a card over the
current pane, replying-to line and post snippet on top), and the zap
sheet became a proper overlay with its own card. Notifications wear
their glyph anatomy: a reaction leads with its emoji, and reposts and
quotes join the pane. Follow and Mute sit grouped on the profile, and
the undo toast tells the truth past its deadline.

Signing got its biggest reliability pass yet: the first sign after login
works against strict signers (the session wears the handshake-completed
client), the first sign after a restart carries the pairing secret the
URI issued, and signing out and back in no longer strands the app on
the login doors (the shell swap now has its listener attached to every
login screen, not just the startup one).

Under the hood: net_guard is the one IP authority (M5 WP1, decision
D57). The pre-release four-lens audit (performance, resources, memory,
security) fixed ten verified findings: zap receipts no longer run a
signature verification per visible row per frame, repost payloads are
parsed once and shared, a closed pane leaves no resident pump tasks
behind, abandoned signer transports are shut down instead of dropped,
the upload client and the video player respect the IP authority,
signer responses log method names only (the log file is now 0600), the
single-instance socket read is capped, and the shell's navigation
dispatch lives in one place. A flaky web-of-trust test stopped wiping
shared state mid-assert.

## 0.5.0 - 2026-11-11

An iteration release with no theme: the composer grew a Video tab (a
deliberate video post is its own NIP-71 event, instant or scheduled,
videos only), thread notes now carry the full action row the timeline has
(reactions, repost, quote, reply, delete, zap), and the gallery carousel's
arrows and position dots page the gallery instead of opening the thread.

Under the hood: paste-time screening refuses wallet and bunker URIs whose
relays point at private addresses, the publish path refuses expired events
and records its own deletions as tombstones at the door, and dependencies
are current (cargo audit reports zero vulnerabilities). A CI workflow now
gates every pull request, with a cargo-deny pass beside the audit.

New in the final cut: a store vacuum (satori-desktop --vacuum rebuilds the
LMDB store offline, recovering the space deletions left behind) and an
Alpine package beside the deb, rpm and flatpak - the first musl build.

## 0.4.0 - 2026-11-08

The media and long-form release: attachments publish right (a note with an
image is a kind-1 note with imeta; replies keep their thread), the Photo
tab returns as its own picture-post surface, a full article composer
(title, summary, cover upload, topics, markdown body) with strikethrough,
task lists and tables in the reader, and hardenened media fetching
(DNS-rebinding-safe resolution, search only asks search-capable relays).

The composer grew a polish pass of its own: previews on every tab (the
article flips to the reader-faithful view, the rest show the draft as its
feed card), session drafts for every post type with a two-step escape (the
first escape saves and stays), a real editor (word motion, word deletion,
line-wise home and end, a body that scrolls), fields that wrap and grow
instead of clipping, video attachments in notes, a live reading time on
the article, the type selector as a segmented control, and one filled
action bar where Publish is unmistakable. A tag bug that kept satori's own
polls from rendering as ballots is fixed.

## 0.3.0 - 2026-11-07

The trust release: web of trust (in your network / outside, always
annotated, never hidden), a duplicate-content spam filter with receipts,
an auditable notification tier, and the four-lens audit fixes.

## 0.2.0 - 2026-11-07

The polish release: live feed engagement, the relay hint model, scheduled
posts, a full visual pass, and the quick wins (keyboard nav, emoji
typeahead, multi-image carousel, alt text, relay health pane).

## 0.1.0 - 2026-11-02

The first release: the whole client, from the follows timeline to inline
video and zaps.
