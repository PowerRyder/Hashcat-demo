# Fernet Passphrase Cracker

GPU-accelerated proof-of-concept that brute-forces Fernet encryption
keys derived from a human-chosen passphrase via a single round of
unsalted SHA-256. Type your passphrase, watch hashcat tear it apart on
your own hardware.

The pattern under attack — common in production codebases — looks like:

```python
fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(passphrase.encode()).digest()))
```

SHA-256 is not a KDF. It has no salt and no work factor, so an attacker
who steals any ciphertext encrypted under that key can recover the
passphrase offline at GPU speed. This script lets you prove that on
your own machine.

## Requirements

- NVIDIA GPU (RTX 20-series or newer recommended; ~7 GH/s on a 3090)
- Recent NVIDIA driver (≥ 535)
- Docker Desktop on Windows/macOS, **or** Docker + NVIDIA Container
  Toolkit on Linux

Verify GPU passthrough works before building:

```
docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
```

If you see your GPU listed, you're set.

## Quick start

```
docker compose run --rm crack
```

First run takes 2–3 minutes (downloads the CUDA runtime image, hashcat
6.2.6, and rockyou.txt — ~134 MB). After that, it starts in seconds.

When the prompt appears, type your passphrase twice (input is hidden).
Hashcat will then run three attack phases on your GPU.

## What the attack does

| Phase | Attack | Keyspace | Catches |
|---|---|---|---|
| 1 | `rockyou.txt × best64.rule` | ~1.1 B | Common words with light mangling (~70% of real-world passwords) |
| 2 | `rockyou.txt × dive.rule` | ~1.4 T (capped) | Almost every human passphrase with any pattern |
| 3 | Mask attacks (13 shapes) | up to 1.8 × 10¹⁶ | "Looks complex" structural shapes (Capital + word + digits + symbol, etc.) |

Each phase prints live progress (`Speed.#1: X.X GH/s`, `Progress`,
`Recovered`). When the passphrase falls — or the budget runs out — the
script reports the result and exits cleanly.

## Expected runtimes (single RTX 3090, ~7 GH/s)

- `password123` — milliseconds (Phase 1)
- `MyComp4ny!` — single-digit seconds (Phase 1 with leet rules)
- `Jenny12!` — ~5 seconds (Phase 3 mask `?u?l?l?l?l?d?d?s`)
- `SecureP4ss2025!` — seconds to a minute (Phase 1 catches it via combined leet+year rules)
- `correct-horse-battery-staple` — survives this script's rockyou pass; falls to a real attacker's xkcd-aware wordlist
- 16+ truly random characters — survives all phases. *That's what a real Fernet key should look like.*

## Flags

```
--max-mask-runtime N   Per-phase runtime cap (default 120 s).
                       Bump to 240 for a more thorough dive.rule pass.
--skip-wordlist        Skip rockyou phases; go straight to masks.
--skip-masks           Run rockyou phases only.
--hashcat PATH         Path to hashcat binary (auto-detected if on PATH).
```

## What this demonstrates

If the cracker finds your passphrase within minutes (and it will, for
almost any passphrase a human can remember), the takeaway is:

- **Don't derive a Fernet key from a passphrase via plain SHA-256.**
- Generate a random key directly:

  ```
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```

  and store that value as your key.
- If a passphrase is unavoidable, run it through Argon2id (with a
  per-deployment salt and a high work factor) before handing it to
  Fernet. Never a single round of SHA-256.

## Defensive use only

Run this against passphrases that are yours, on hardware that's yours,
to verify a finding in your own security review. Do not point it at
hashes or passphrases that don't belong to you.

## License

MIT — see [LICENSE](LICENSE).
