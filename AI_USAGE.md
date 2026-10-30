# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

Muse (Meta AI assistant) was used for all three parts of the task: implementing
`bayyina_guard/validation.py`, `bayyina_guard/policy.py`, and `bayyina_guard/passwords.py`
from the template starter, running the 5 public tests, and running an additional edge-case
check script covering the hidden-test cases described in the task (path tricks, invisible/bidi
characters, last-extension rules, type/signature mismatch, bool/float sizes, ASCII-only matter
ids, denial precedence, exact tenant matching, legacy-hash verification, and truncated-hash
rejection). No other AI tool was used for the code.

## What AI got wrong

Two happy-path traps that the public tests alone would not have caught, found by running the
edge-case checks above before finalising:

1. A matter-id check written with a Unicode-digit matcher would accept Arabic-Indic digits.
   Changed to ASCII `[0-9]` only, plus an explicit ASCII check, so Arabic-Indic digits fail.
2. A password verifier that lets the stored string choose the comparison length would accept a
   hash truncated by four characters by comparing only a prefix. Changed to compare the full
   derived key against an exactly-32-byte stored key with `hmac.compare_digest`, so a truncated
   hash returns False. The verifier also validates n, r, p, salt length, and key length before
   calling scrypt, so a stored value with an out-of-range p returns False quickly instead of
   running for minutes.

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?

Prevents Information Leakage, returning 403 shows that the contract is real or exists. But returning 404 means it totally hides the contract from users who are not allowed to see it.

Prevents Resource Enumeration, it stops people who might attack by checking sequential IDs like /contracts/101 so they can't figure out which contracts are valid in the system.

2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?

Prevents Truncation Bypass: Matching only a prefix allows for easy bypass of truncated or corrupt hashes with weak passwords. Maintains Cryptographic Entropy : To maintain the appropriate strength of cryptography ( $ 2^ { 256 } $ complexity ), 32 bytes ( 256 bits ) are needed. Ensures Data Integrity: If the hash is less than 32 bytes, the data is considered tampered with or malformed and should immediately fail validation.
