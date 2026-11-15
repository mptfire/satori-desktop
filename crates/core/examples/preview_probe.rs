//! Probe: run the REAL fetch_link_preview pipeline against URLs.
use satori_core::media;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    for url in std::env::args().skip(1) {
        let verdict = media::fetch_link_preview(&url).await;
        match verdict {
            Ok(p) => println!(
                "{url}\n  -> OK site={} title={:?} img={:?}\n",
                p.site, p.title, p.image
            ),
            Err(e) => println!("{url}\n  -> ERR {e:?}\n"),
        }
    }
    Ok(())
}
