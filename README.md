# GhostMesh

A privacy-first iOS chat and voice-call app with no server, ever. Every
device is both client and server — there is nothing for anyone to log
because nothing exists to log it.

## What it does

- **End-to-end encryption** for text and voice, forward-secret per message
  and per audio frame (Signal-style X3DH + Double Ratchet, from-scratch
  implementation — see Security below).
- **No server, no accounts, no phone numbers.** Your identity is a
  Curve25519 key you generate on-device. Contacts are added by scanning
  each other's QR code.
- **Mesh networking.** Nearby devices connect directly over
  Bluetooth/WiFi (MultipeerConnectivity) with no internet at all. More
  people running the app nearby means more relay paths and better range.
- **Tor routing.** When a contact isn't nearby, messages and calls route
  through an embedded Tor client to their onion address. No ISP, carrier,
  or server operator — because there is no server — ever sees who's
  talking to whom.
- **No message history by default.** Chats live in memory only unless you
  turn on local history in Settings, in which case they're kept
  Keychain-encrypted on your device only.

## Project layout

```
GhostMesh.xcodeproj/       Xcode project (SPM dependency: swift-tor)
GhostMesh/
  GhostMeshApp.swift       App entry point
  Crypto/
    Identity.swift         Curve25519 identity keypair + QR pairing bundle
    X3DH.swift              Initial key agreement (Signal-style)
    DoubleRatchet.swift     Per-message forward-secret ratchet (text)
    CallSession.swift       Per-call ephemeral DH + per-frame ratchet (voice)
    RatchetPrimitives.swift Shared KDF building blocks used by both ratchets
  Models/
    Contact.swift, ChatMessage.swift, CallModels.swift
  Networking/
    MeshTransport.swift     MultipeerConnectivity flood-relay mesh
    TorTransport.swift      Embedded Tor client + onion inbox + call streams
    SOCKS5Client.swift      Minimal SOCKS5 client for reaching .onion addresses
    MessageRouter.swift     Picks mesh vs. Tor vs. retry-queue per message
  Audio/
    CallAudioEngine.swift   Mic capture, jitter buffer, playback
  ViewModel/
    AppViewModel.swift, CallViewModel.swift
  Views/
    ContentView.swift, ChatView.swift, PairingView.swift,
    SettingsView.swift, CallView.swift
```

## Building

Requires Xcode with iOS 18 SDK support (Xcode 16+). Open
`GhostMesh.xcodeproj` — the `swift-tor` package resolves automatically on
first build.

No Mac? `.github/workflows/build-ipa.yml` builds an **unsigned** IPA on
GitHub's macOS runners. Run it manually from the Actions tab, download the
IPA artifact, then sideload it with SideStore or AltStore PAL — no Mac or
paid developer account required for either step.

## Security status — read this before relying on it

This is a from-scratch implementation of the Signal Protocol's design
(X3DH + Double Ratchet), not Signal's own audited `libsignal` code.
Cryptographically it follows the same published design, but it has **not
been independently reviewed or audited**. Two people should verify each
other's identity fingerprint (shown in Settings) out of band before
trusting a pairing.

Tor voice calls inherit Tor's latency — typically several hundred ms to a
couple of seconds. Fine for a walkie-talkie-style exchange, not for
fast back-and-forth conversation. Mesh calls (no internet, direct local
connection) are close to real-time.

If your safety genuinely depends on this app, get the crypto reviewed by
someone qualified before you rely on it. Treat this as a solid foundation
and a working prototype, not a finished, audited product.

## License

Please respect my license and code as it's my property. If not
respected I may take legal action.

All rights reserved — see [`LICENSE`](./LICENSE) for the full terms. No
part of this code may be used, copied, modified, or redistributed
without explicit written permission.
