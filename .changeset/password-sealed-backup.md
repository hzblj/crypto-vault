---
'@hzblj/crypto-vault': minor
---

Backups under a password. `vault.backup(id, {password, prompt})` opens an entry after the system prompt and has the `@hzblj/nitro-crypto` engine seal its entropy natively (Argon2id at 64 MiB, XChaCha20-Poly1305): 87 to 103 bytes that are safe to store anywhere, as only the password opens them. `vault.restore(id, backup, {password, access?, prompt?})` opens a backup natively, straight into a new entry under this device's hardware; JavaScript never holds the entropy either way. Passwords are NFC-normalized and need at least 8 characters (`MIN_PASSWORD_LENGTH`). New error codes `WEAK_PASSWORD`, `WRONG_PASSWORD` and `INVALID_BACKUP`; `vault.backupSupported` says whether the engine seals backups (ADR 0002). Needs `@hzblj/nitro-crypto` 0.1.4.
