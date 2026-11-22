# Audi MHI2 CN P0916 Native Wireless CarPlay Research Showcase

**English** | [简体中文](README.md)

This project investigates **pure-RAM native wireless Apple CarPlay** on the classic Audi **MHI2 (`MHI2_CN_AU37x_P0916` / MU0916, QNX 6.5 ARM32)** head unit—reusing the onboard Bluetooth, vehicle Wi‑Fi access point, and stock `libairplay.so (210.81)` without modifying OEM flash partitions, while preserving wired USB CarPlay.

> [!WARNING]
> **Copyright & Anti-Commercialization Notice**
>
> All copyrights to the original research notes, documentation, and source code in this repository belong exclusively to the author (**GitHub: `@emotional-lau` / Weibo & Autohome: `@emotional_lau`**), All Rights Reserved.
>
> **Unauthorized commercialization of any kind is strictly prohibited** (including reselling source code or builds, paid installation/flashing services, commercial bundling, or for-profit redistribution). Viewing and discussion are permitted strictly for personal, non-commercial study provided this notice remains intact. See [LICENSE](LICENSE).

---

> [!IMPORTANT]
> **Public Repository Scope (Research Showcase)**
>
> - **This is an incomplete, work-in-progress research showcase intended strictly for technical discussion and learning.**
> - To prevent commercial cloning and unauthorized reselling, **this public repository contains only architecture documentation, progress tracking, and standalone firmware-independent C cryptographic primitives (`src/crypto/`)**.
> - All head-unit-specific components—including `libairplay.so` / `dio_manager` object layouts and fixed addresses, runtime Hook implementations, HAP pairing/control state machines, the wireless audio relay, Bluetooth iAP2/RFCOMM integration, build/graft toolchains, and vehicle deployment frameworks—**are kept in a private repository and are not distributed publicly**.

---

## 1. High-Level Architecture Concept

Without altering OEM flash partitions, the approach focuses on pure-RAM runtime interposition and reuse of existing OEM infotainment subsystems:

```mermaid
flowchart LR
    iPhone["iPhone (iOS CarPlay)"] <-->|"Bluetooth RFCOMM (iAP2 Auth & Wi-Fi Handover)"| BTHook["Bluetooth Service Extension Layer"]
    iPhone <-->|"Wi-Fi Control / Event (HAP + ChaCha20)"| AirPlayHook["Stock AirPlay 210.81 Runtime Layer"]
    iPhone -->|"H.264 Video / AAC-LC & Opus Audio"| AirPlayHook
    BTHook -->|"Session Trigger"| SI["System Integrator Layer (SI / DIO)"]
    AirPlayHook -->|"Decrypted Frames & Stock PCM"| StockMMI["OEM Display & nvaudio Pipeline"]
    StockMMI -->|"MMI Rotary Knob / Center Display / Audio"| User["In-Vehicle Experience"]
```

---

## 2. Current Real-Vehicle Progress

- **Verified & working on real vehicle**:
  - Bluetooth iAP2 authentication response and Wi‑Fi credential handover trigger;
  - Wireless CarPlay control session discovery, HAP pairing/verification, and `ChaCha20-Poly1305` encrypted control & event channels;
  - `800×480` H.264 main display output, smooth MMI rotary knob input, and multi-cycle teardown/reconnect stability.
- **In progress / incomplete**:
  - **Wireless audio path (real-car debugging)**: The iPhone audio output picker already detects and selects CarPlay, and media audio stream setup triggers `nvaudio` on the head unit; currently resolving an immediate stream teardown during media playback `SETUP` handshake;
  - **Pairing persistence & Bluetooth cleanup (pending)**: RAM-only test runs reset pairing identity across reboots, causing manual re-pairing and modal dialog stalls; persistent identity storage and post-session Bluetooth link teardown are pending;
  - **No-SIM notification suppression (pending)**;
  - **Audi Virtual Cockpit cluster map projection compatibility (pending)**.

---

## 3. Public Directory Contents

This public showcase includes only standalone generic C cryptographic primitives and QNX base ABI type headers (3 source files), containing **no target firmware offsets or head-unit Hook implementations**:

| File | Description |
| --- | --- |
| `src/crypto/wcp_crypto.h` / `wcp_crypto.c` | Standalone C cryptographic primitives (SRP-6a, X25519, Ed25519, SHA-512, HKDF-SHA-512, ChaCha20-Poly1305) |
| `src/crypto/qnx65_abi.h` | Generic QNX 6.5 base types and POSIX/Socket constant definitions |

---

## 4. Referenced Projects & Attribution

Research and protocol analysis referenced the following 4 open-source projects (with specific areas credited):

1. **[joeyQuery/MHI2-wirelessCarPlay](https://github.com/joeyQuery/MHI2-wirelessCarPlay)**
   - **Referenced for**: Classic MHI2 Bluetooth iAP2 / DIO / AirPlay boundary tracing and firmware comparison notes.

2. **[korhojoa/mib2-extenders](https://github.com/korhojoa/mib2-extenders)**
   - **Referenced for**: MIB2 High (QNX) Bluetooth service lifecycle management, Wi‑Fi AP integration, and platform extension architecture.

3. **[luka-dev/mib2q-carplay-rgi](https://github.com/luka-dev/mib2q-carplay-rgi)**
   - **Referenced for**: Wireless CarPlay protocol stages (iAP2 authentication & Wi‑Fi handover parameters, Bonjour control discovery & session trigger, system integrator architecture, and stock AirPlay `210.81` pairing/streaming boundaries).

4. **[congobg/MHI2Q_WiFi_CarPlay](https://github.com/congobg/MHI2Q_WiFi_CarPlay)**
   - **Referenced for**: Stock `libairplay.so (210.81)` wireless audio relay design (`/info` audio format advertisement, stream type mapping, UDP decoding paced against the stock jitter buffer playhead into PCM, and Opus microphone uplink).

---

## 5. Disclaimer

- This repository is shared strictly for **personal technical learning and research** into automotive QNX systems and wireless CarPlay protocols; no plug-and-play packages or commercial solutions are provided.
- Copyright belongs exclusively to the author (GitHub: `@emotional-lau` / Weibo & Autohome: `@emotional_lau`). Unauthorized commercial use or reselling is strictly prohibited. See [LICENSE](LICENSE).
