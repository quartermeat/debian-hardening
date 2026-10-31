# Phone public key import

Status: done

Added `import_phone_key.py` and `test_import_phone_key.py`. The script checks for one authorized adb device, pulls `/sdcard/Download/phone.pub` or reads `--file`, rejects private keys and malformed Ed25519 public key wire data, prints the fingerprint, and asks for confirmation before running phase 2 with `sudo`. It supports `--remote`, `--label`, `--dry-run`, `--yes`, and `--delete-remote`. The temporary key is removed after the command completes.

Checks passed:

- `python3 -m py_compile import_phone_key.py`
- `python3 -m unittest -v test_import_phone_key.py test_phase2_ssh.py` (16 tests)
- `python3 import_phone_key.py --help`
- `git diff --check`

No real adb pull or sudo install was run. No commit was made.
