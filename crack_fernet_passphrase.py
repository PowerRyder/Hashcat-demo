r"""GPU brute-force demo for Fernet keys derived from a passphrase.

WHAT IT DOES
------------
Many codebases generate a Fernet encryption key from a human-chosen
passphrase by feeding it through a single round of unsalted SHA-256:

    derived = sha256(passphrase).digest()
    fernet  = Fernet(base64.urlsafe_b64encode(derived))

This pattern is widespread — it's the obvious thing to do when you want
operators to type a memorable key — and it's catastrophically weak.
SHA-256 is not a KDF: it has no salt and no work factor, so an attacker
who steals any ciphertext encrypted under that key can brute-force the
passphrase offline at GPU speed.

This script lets you prove that to yourself. You type a passphrase you
want to test. The script:

  1. Computes its SHA-256 hex digest — the same 32 bytes the derivation
     above would produce. We hand this digest to hashcat as if the
     attacker had already extracted it from a leaked secret.
  2. Writes the digest to a temp .hash file.
  3. Invokes hashcat (mode 1400 = SHA-256) against the digest with two
     phases: first rockyou.txt × best64.rule (a quick pass), then
     rockyou.txt × dive.rule (the heavy attacker-grade pass). If both
     miss, escalates to mask attacks that cover the common "looks
     complex but isn't" shapes (`Capital + word + digits + symbol`,
     etc.).
  4. Streams hashcat's live progress to your terminal.
  5. When hashcat finds the passphrase — or finishes without finding it
     — reports wall-clock time and the achieved guesses per second.

NOTE ON REALISM
---------------
Hashcat attacks the raw SHA-256 hash directly. A real attacker who only
has Fernet ciphertext (not a bare hash) must additionally verify each
candidate via Fernet's HMAC check — a few extra SHA-256 ops per try,
roughly 3x slower than this demo. If hashcat cracks your passphrase in
5 seconds here, expect ~15 seconds of real-attacker wall time against
the ciphertext. Same order of magnitude — same conclusion.

HOW TO RUN
----------
The folder containing this script also has a Dockerfile and
docker-compose.yml that handle hashcat install + GPU passthrough:

    docker compose run --rm crack

Docker Desktop on Windows + a recent NVIDIA driver does WSL2 GPU
passthrough automatically — no manual hashcat install, no separate
NVIDIA Container Toolkit setup needed.

If you'd rather run the script directly on the host (skip Docker),
install hashcat via `winget install hashcat.hashcat` (Windows) or
`sudo apt install hashcat` (Linux), then run:

    python3 crack_fernet_passphrase.py

DEFENSIVE USE ONLY
------------------
Run this against passphrases that are yours. The point is to prove to
yourself, on your own hardware, that a passphrase-derived Fernet key is
not safe at rest.
"""

import argparse
import base64
import getpass
import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# Real-attacker wordlist + rules. These are the same files a pentester
# or breach-forensics analyst would use against a leaked hash:
#
# - rockyou.txt: 14.3 million real passwords from the 2009 RockYou
#   breach. Effectively a catalogue of every password a human has
#   ever picked. Bundled into the image during `docker build` from
#   the naive-hashcat GitHub mirror.
#
# - best64.rule: 77 hand-tuned mangling rules that catch ~70% of
#   real-world passwords when paired with rockyou. Fast pass.
#
# - dive.rule: 99,092 rules covering nearly every realistic
#   transformation (capitalization, leet, prefix/suffix combinations,
#   keyboard walks, etc.). Massive but still GPU-friendly.
#
# Both rule files ship with upstream hashcat in /opt/hashcat/rules/.
ROCKYOU_WORDLIST = Path('/opt/hashcat/wordlists/rockyou.txt')
HASHCAT_RULES_BEST64 = Path('/opt/hashcat/rules/best64.rule')
HASHCAT_RULES_DIVE = Path('/opt/hashcat/rules/dive.rule')


# Mask patterns — each represents a common "complex" password shape.
# Hashcat charsets:  ?l lowercase, ?u uppercase, ?d digit,
#                    ?s symbol (!@#$%^&*()-_+=...), ?a all printable
MASK_ATTACKS = [
    # 6-8 chars, all-lowercase — surrenders in seconds
    '?l?l?l?l?l?l',          # 6 lowercase
    '?l?l?l?l?l?l?l',        # 7 lowercase
    '?l?l?l?l?l?l?l?l',      # 8 lowercase
    # 8 chars, mixed-case
    '?u?l?l?l?l?l?l?l',      # Sentence-case lowercase
    # 8 chars, the "looks complex" pattern
    '?u?l?l?l?l?d?d?s',      # Capital + 4 lower + 2 digit + symbol  (e.g. Jenny12!)
    '?l?l?l?l?l?l?d?d',      # 6 lower + 2 digit
    '?u?l?l?l?l?l?d?s',      # Capital + 5 lower + digit + symbol
    # 9-10 chars
    '?u?l?l?l?l?l?l?d?d',
    '?u?l?l?l?l?l?l?d?d?s',
    '?u?l?l?l?l?l?l?l?d?d',  # 10 chars typical complex
    '?u?l?l?l?l?l?l?l?l?d',
    # 11-12 chars
    '?u?l?l?l?l?l?l?l?l?d?d',
    '?u?l?l?l?l?l?l?l?l?d?d?s',
]


def derive_sha256_hex(passphrase: str) -> str:
    """Single round of SHA-256 over the UTF-8 passphrase, returned as
    hex so hashcat can ingest it under mode 1400."""
    return hashlib.sha256(passphrase.encode('utf-8')).hexdigest()


def derive_fernet_key(passphrase: str) -> bytes:
    """Full Fernet-from-passphrase derivation — printed back so you can
    visually confirm this script's hash matches whatever derivation
    the application under test uses."""
    return base64.urlsafe_b64encode(
        hashlib.sha256(passphrase.encode('utf-8')).digest()
    )


def find_hashcat(explicit_path: str | None) -> str | None:
    if explicit_path:
        return explicit_path if Path(explicit_path).is_file() else None
    on_path = shutil.which('hashcat')
    if on_path:
        return on_path
    # Common local install locations (Windows fallback if not in PATH)
    candidates = [
        Path.home() / 'Downloads' / 'hashcat-6.2.6' / 'hashcat.exe',
        Path.home() / 'hashcat' / 'hashcat.exe',
        Path('C:/hashcat/hashcat.exe'),
        Path('C:/Tools/hashcat/hashcat.exe'),
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def print_install_instructions() -> None:
    print()
    print('hashcat is not installed.')
    print()
    print('Easiest: use the Dockerfile bundled in this folder.')
    print('  docker compose run --rm crack')
    print()
    print('Or install directly:')
    print('  Windows:  winget install hashcat.hashcat')
    print('  Linux:    sudo apt install hashcat')
    print('  Then re-run this script.')
    print()


def check_attack_files() -> bool:
    """Confirm the real-attacker wordlist + rule files are present.
    The Dockerfile downloads rockyou.txt and hashcat's release ships
    best64.rule and dive.rule. If anything's missing, the image needs
    rebuilding."""
    missing = [
        p for p in [ROCKYOU_WORDLIST, HASHCAT_RULES_BEST64, HASHCAT_RULES_DIVE]
        if not p.exists()
    ]
    if not missing:
        return True
    print()
    print('[!] Required attack files not found in the image:')
    for p in missing:
        print(f'    - {p}')
    print()
    print('[!] Rebuild the container so the Dockerfile can download them:')
    print('       docker compose build crack')
    return False


def run_hashcat(
    hashcat: str,
    hash_path: Path,
    workdir: Path,
    *args: str,
) -> tuple[int, float]:
    """Invoke hashcat and stream its output. Returns (exit_code, secs)."""
    cmd = [
        hashcat,
        '-m', '1400',           # SHA-256
        '--status',
        '--status-timer', '3',
        '--potfile-path', str(workdir / 'demo.potfile'),
        '--session', 'fernet-demo',
        '--restore-disable',
        str(hash_path),
        *args,
    ]
    print(f'  $ {" ".join(cmd)}')
    print()
    start = time.monotonic()
    # Inherit stdout/stderr so the user sees hashcat's live progress.
    proc = subprocess.run(cmd, cwd=str(workdir))
    return proc.returncode, time.monotonic() - start


def parse_cracked(potfile: Path, target_hash: str) -> str | None:
    """Read the potfile and return the cracked passphrase, if any.
    Hashcat writes lines like `<hash>:<plaintext>`."""
    if not potfile.exists():
        return None
    for line in potfile.read_text(encoding='utf-8', errors='replace').splitlines():
        if line.startswith(target_hash):
            _, _, plaintext = line.partition(':')
            return plaintext
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description='GPU brute-force demo for SHA-256 passphrase-derived Fernet keys.'
    )
    parser.add_argument(
        '--hashcat',
        help='Full path to hashcat binary (auto-detected if on PATH).',
    )
    parser.add_argument(
        '--skip-wordlist',
        action='store_true',
        help='Skip the rockyou.txt phases and go straight to masks.',
    )
    parser.add_argument(
        '--skip-masks',
        action='store_true',
        help='Skip mask attacks (rockyou + rules only).',
    )
    parser.add_argument(
        '--max-mask-runtime',
        type=int,
        default=120,
        help='Per-phase runtime cap in seconds for dive.rule and each '
             'mask attack. Default 120. Increase to 240 for a more '
             'thorough dive.rule pass (full exhaust takes ~4 min on a 3090).',
    )
    args = parser.parse_args()

    print('=' * 72)
    print(' Fernet passphrase GPU brute-force demo')
    print(' Attacks the pattern: Fernet(b64(sha256(passphrase)))')
    print('=' * 72)
    print()

    hashcat = find_hashcat(args.hashcat)
    if not hashcat:
        print_install_instructions()
        sys.exit(1)
    if not check_attack_files():
        sys.exit(1)
    print(f'[*] Using hashcat: {hashcat}')
    rockyou_size = ROCKYOU_WORDLIST.stat().st_size
    print(f'[*] Wordlist:      {ROCKYOU_WORDLIST} ({rockyou_size // 1024 // 1024} MB)')
    print(f'[*] Rules:         {HASHCAT_RULES_BEST64.name} + {HASHCAT_RULES_DIVE.name}')
    print()

    passphrase = getpass.getpass('Passphrase to attack (input hidden): ')
    if not passphrase:
        print('(empty — exiting)')
        sys.exit(0)
    confirm = getpass.getpass('Confirm passphrase:                 ')
    if passphrase != confirm:
        print('(mismatch — exiting)')
        sys.exit(0)

    target_hash = derive_sha256_hex(passphrase)
    fernet_key = derive_fernet_key(passphrase)

    print()
    print('[*] Target derivation:')
    print(f'    SHA-256(passphrase) = {target_hash}')
    print(f'    Fernet key          = {fernet_key.decode()}')
    print()
    print('[*] These are the two values any application using this')
    print('    derivation would produce from your passphrase. Hashcat')
    print('    now attacks the SHA-256 step on your GPU.')
    print()

    with tempfile.TemporaryDirectory(prefix='fernet-crack-') as tmp:
        workdir = Path(tmp)
        hash_path = workdir / 'target.hash'
        hash_path.write_text(target_hash, encoding='utf-8')
        potfile = workdir / 'demo.potfile'

        total_started = time.monotonic()

        # Phase 1 — rockyou.txt + best64.rule. 14.3M passwords × 77
        # rules ≈ 1.1B candidates. On an RTX 3090 (~6.9 GH/s) this
        # finishes in well under a second. Catches the bulk of
        # human-chosen passwords; if your passphrase is just a common
        # word with light mangling, it dies here.
        if not args.skip_wordlist:
            print('-' * 72)
            print('[Phase 1] rockyou.txt × best64.rule')
            print('  Wordlist: rockyou.txt (14.3M real-world passwords)')
            print('  Rules:    best64.rule (77 high-yield transformations)')
            print('  Keyspace: ~1.1 billion candidates')
            print('-' * 72)
            run_hashcat(
                hashcat, hash_path, workdir,
                '-a', '0',
                str(ROCKYOU_WORDLIST),
                '-r', str(HASHCAT_RULES_BEST64),
            )
            cracked = parse_cracked(potfile, target_hash)
            if cracked:
                _report_success(cracked, total_started, passphrase)
                return

            # Phase 2 — rockyou.txt + dive.rule. The "real attack" pass
            # most pentesters and breach analysts run. 14.3M × 99,092
            # rules ≈ 1.4 trillion candidates; capped to a fixed wall
            # time below since exhausting the whole space takes ~4
            # minutes on a 3090 and we want a clear time-boxed phase.
            print()
            print('-' * 72)
            print('[Phase 2] rockyou.txt × dive.rule  (the serious pass)')
            print('  Wordlist: rockyou.txt')
            print('  Rules:    dive.rule (99,092 transformations)')
            print(f'  Keyspace: ~1.4 trillion candidates (capped at {args.max_mask_runtime}s)')
            print('-' * 72)
            run_hashcat(
                hashcat, hash_path, workdir,
                '-a', '0',
                str(ROCKYOU_WORDLIST),
                '-r', str(HASHCAT_RULES_DIVE),
                '--runtime', str(args.max_mask_runtime),
            )
            cracked = parse_cracked(potfile, target_hash)
            if cracked:
                _report_success(cracked, total_started, passphrase)
                return

        # Phase 3.X — mask attacks. For passphrases that aren't a
        # mangled real-world password at all (random-ish strings that
        # still fit common shape patterns).
        if not args.skip_masks:
            for i, mask in enumerate(MASK_ATTACKS, 1):
                print()
                print('-' * 72)
                print(f'[Phase 3.{i}/{len(MASK_ATTACKS)}] Mask attack: {mask}')
                print(f'  (~{_mask_keyspace(mask):.2e} candidates; cap {args.max_mask_runtime}s)')
                print('-' * 72)
                run_hashcat(
                    hashcat, hash_path, workdir,
                    '-a', '3',
                    mask,
                    '--runtime', str(args.max_mask_runtime),
                )
                cracked = parse_cracked(potfile, target_hash)
                if cracked:
                    _report_success(cracked, total_started, passphrase)
                    return

        # Not cracked
        elapsed = time.monotonic() - total_started
        print()
        print('=' * 72)
        print(f'[*] NOT CRACKED after {elapsed:.0f}s of attack.')
        print()
        print('    Your passphrase survived:')
        print('      - rockyou.txt (14.3M passwords) × best64.rule')
        print(f'      - rockyou.txt × dive.rule (99K rules, {args.max_mask_runtime}s budget)')
        print(f'      - {len(MASK_ATTACKS)} mask patterns up to 12 chars')
        print()
        print('    That is genuinely strong against this exact attack — but a')
        print('    real attacker may still find it with:')
        print('      - larger lists (Have I Been Pwned breach corpus = 800M+)')
        print('      - longer dive.rule runtime (4 min exhausts the whole')
        print('        rockyou × dive space on a single 3090)')
        print('      - longer masks or hybrid attacks (mask+wordlist, hybrid)')
        print('      - target-customised wordlists (project names, owner')
        print('        names, birthdays — all trivially gathered)')
        print()
        print('    True safety: stop using a passphrase. Generate a random')
        print('    Fernet key directly with:')
        print('       python -c "from cryptography.fernet import Fernet; \\')
        print('                  print(Fernet.generate_key().decode())"')
        print('    and store that value directly. No derivation step = no')
        print('    brute-force surface, regardless of attacker hardware.')
        print('=' * 72)


def _mask_keyspace(mask: str) -> int:
    """Approximate candidate count for a hashcat mask."""
    sizes = {'?l': 26, '?u': 26, '?d': 10, '?s': 33, '?a': 95, '?h': 16}
    total = 1
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask):
            total *= sizes.get(mask[i:i + 2], 1)
            i += 2
        else:
            total *= 1
            i += 1
    return total


def _report_success(cracked: str, started: float, original: str) -> None:
    elapsed = time.monotonic() - started
    print()
    print('=' * 72)
    print(f'[!] CRACKED in {elapsed:.2f} seconds')
    print(f'[!] Passphrase was: {cracked!r}')
    if cracked == original:
        print('[!] Match confirmed against the typed passphrase.')
    else:
        print('[!] (Hashcat output differs from typed; encoding issue?)')
    print('=' * 72)
    print()
    print('What this means in practice:')
    print('  - An attacker who steals any ciphertext encrypted under a')
    print('    Fernet key derived from this passphrase can run this')
    print('    exact attack offline. No traffic to a server, no log')
    print('    entries, no alerts.')
    print('  - Once they recover the passphrase, every value protected')
    print('    by that Fernet key (config secrets, stored credentials,')
    print('    session tokens, anything else) decrypts trivially.')
    print('  - Mitigation: do not derive keys from passphrases at all.')
    print('    Use Fernet.generate_key() to mint a real random key and')
    print('    store that value directly. If a passphrase is required,')
    print('    run it through Argon2id (with a per-deployment salt and')
    print('    a high work factor) before handing it to Fernet — never')
    print('    a single round of SHA-256.')
    print()


if __name__ == '__main__':
    main()
