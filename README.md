# Peek-in QR

Peek-in QR is a local-first, privacy-preserving Android QR security gate application built with Flutter/Dart and native Kotlin Android platform channels, augmented with an optional FastAPI/Redis threat reputation service.

## Architecture & Repository Structure

- `apps/mobile/`: Flutter Android application (minimum SDK 26, Quick Settings Tile, camera QR scanner, typed safe payload parsers, deterministic local rule engine, SQLite knowledge base, and consent gateway).
- `services/reputation/`: Lightweight Python FastAPI REST service with Redis TTL cache for privacy-preserving reputation lookup.
- `scripts/`: Security enforcement, toolchain validation, and secret scanning automation.
- `.github/workflows/`: CI pipeline configurations.

## Security Invariants

1. Untrusted Decode: All decoded QR payloads are inert upon scan. No automatic URL navigation, payment, phone dialing, or Wi-Fi joining occurs during analysis.
2. Invariant Pipeline: `scan -> parse -> rules/KB/ML/(optional net) -> fusion -> diagnostics -> consent -> ActionGateway`.
3. Tri-state Fusion: Verdicts are strictly `VERIFIED`, `UNKNOWN`, or `SUSPICIOUS`. `VERIFIED` requires positive cryptographic/authenticated proof; `SUSPICIOUS` blocks by default; `UNKNOWN` requires explicit informed confirmation.
4. Privacy: No raw QR payloads, payment details, full URL query parameters, or Wi-Fi passwords are transmitted or logged.
