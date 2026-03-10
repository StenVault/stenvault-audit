"""
Few-shot examples for audit prompts.
Contains real violation examples and false positive examples specific to CloudVault.
"""

# Real violations — these help the model understand what actual issues look like
VIOLATION_EXAMPLES = """
FEW-SHOT EXAMPLES — Real violations:

Example 1 (IV reuse — CRITICAL):
```typescript
  260 | const iv = new Uint8Array(12)
  261 | // BUG: iv is all-zeros, never filled with random bytes
  262 | const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)
```
Finding: {"checklist_item": "C01", "severity": "critical", "line_start": 260, "line_end": 262, "finding": "IV is allocated but never filled with crypto.getRandomValues() — all-zero IV breaks AES-GCM security", "evidence": "const iv = new Uint8Array(12)", "suggestion": "Add crypto.getRandomValues(iv) before use"}

Example 2 (Weak key derivation — HIGH):
```typescript
  45 | const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'AES-GCM', false, ['encrypt'])
```
Finding: {"checklist_item": "KD01", "severity": "high", "line_start": 45, "line_end": 45, "finding": "Password used directly as key without KDF (Argon2id/PBKDF2) — vulnerable to brute force", "evidence": "new TextEncoder().encode(password)", "suggestion": "Derive key using Argon2id with salt before importKey"}

Example 3 (Missing auth tag check — HIGH):
```typescript
  180 | const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  181 | // Immediately uses decrypted data without checking for decryption failure
  182 | return JSON.parse(new TextDecoder().decode(decrypted))
```
Finding: {"checklist_item": "C08", "severity": "high", "line_start": 180, "line_end": 182, "finding": "Decrypted data used without try/catch — if auth tag is invalid, subtle.decrypt throws but error is not handled", "evidence": "JSON.parse(new TextDecoder().decode(decrypted))", "suggestion": "Wrap decrypt in try/catch to handle authentication failures explicitly"}
"""

# False positive examples — these help the model avoid common mistakes
FALSE_POSITIVE_EXAMPLES = """
FEW-SHOT EXAMPLES — Known false positives (do NOT flag these):

False Positive 1 (deriveChunkIV is safe by design):
```typescript
  88 | const chunkIV = await deriveChunkIV(fileKey, fileId, chunkIndex)
  89 | const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: chunkIV }, fileKey, chunk)
```
NOT a violation: deriveChunkIV uses HKDF with (fileKey, fileId, chunkIndex) as inputs. The IV is unique per chunk because chunkIndex changes. This is a deterministic-IV scheme that is safe for AES-GCM when inputs are unique.

False Positive 2 (extractable: true is intentional):
```typescript
  120 | const masterKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
```
NOT a violation: extractable=true is required here because the master key needs to be wrapped (exported) with AES-KW for device approval flow. The key is wrapped before any storage.

False Positive 3 (hardcoded salt is a domain separator):
```typescript
  55 | const salt = new TextEncoder().encode('cloudvault_recovery_code_salt_v1')
```
NOT a violation: This is a domain separation string for HKDF, not a per-user salt. The actual randomness comes from the master key input. Hardcoded domain separators are standard practice (RFC 5869).
"""

# Combined for injection into prompts
ALL_FEW_SHOT_EXAMPLES = VIOLATION_EXAMPLES + "\n" + FALSE_POSITIVE_EXAMPLES


def get_few_shot_examples() -> str:
    """Return all few-shot examples formatted for prompt injection."""
    return ALL_FEW_SHOT_EXAMPLES


def get_violation_examples() -> str:
    """Return only violation examples."""
    return VIOLATION_EXAMPLES


def get_false_positive_examples() -> str:
    """Return only false positive examples."""
    return FALSE_POSITIVE_EXAMPLES
