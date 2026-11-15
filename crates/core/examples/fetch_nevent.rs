//! Probe: decode a nevent, fetch the raw event from one public relay over
//! a bare websocket REQ (self-contained: tokio-tungstenite only).
use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use tokio_tungstenite::connect_async;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nevent = std::env::args().nth(1).expect("nevent arg");
    let bech = nevent.strip_prefix("nostr:").unwrap_or(&nevent);
    let Nip19::Event(e) = Nip19::from_bech32(bech)? else {
        panic!("not an nevent");
    };
    println!("event id: {}", e.event_id);

    let (mut ws, _) = connect_async("wss://nos.lol").await?;
    let req = format!(r#"["REQ","probe",{{"ids":["{}"]}}]"#, e.event_id);
    ws.send(req.into()).await?;
    while let Some(msg) = ws.next().await {
        let msg = msg?;
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            if text.contains("EOSE") {
                break;
            }
            if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&text)
                && arr[0] == "EVENT"
            {
                println!("kind: {}", arr[2]["kind"]);
                println!("content: {}", arr[2]["content"]);
                println!("tags: {}", serde_json::to_string_pretty(&arr[2]["tags"])?);
            }
        }
    }
    Ok(())
}
