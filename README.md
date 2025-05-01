markdown
# Python Code Obfuscator with AES-256-GCM Protection

A robust code protection solution combining military-grade encryption and code obfuscation techniques.

## Features

- 🔐 **AES-256-GCM Encryption** - Industry-standard authenticated encryption
- 🛡 **Dual Key Input** - File-based or interactive CLI key entry
- 🧩 **Code Obfuscation** - Random variable names and structure flattening
- 🚫 **Anti-Tampering** - Integrity verification via GCM authentication
- 📦 **Standalone Output** - No external dependencies required
- ⚙ **Marshal Integration** - Protects Python bytecode directly

## Requirements

- Python 3.6+
- `cryptography` package

## Installation

```bash
pip install cryptography

## Usage

### Basic Obfuscation
```bash
python obfuscator.py input.py output.py
```
Generates:
- `output.py` - Obfuscated code
- Displays base85-encoded emergency key in console

### Key File Mode
```bash
python obfuscator.py input.py output.py secret.key
```
Generates:
- `output.py` - Protected code
- `key.txt` - Binary key file

### Running Obfuscated Code
```bash
python output.py
```
Automatically looks for:
1. `key.txt` (default filename)
2. Prompts for manual key entry if file missing

## Key Management

### Saving Keys
```bash
# Save emergency key to file
echo "EMERGENCY_KEY" > key.txt
```

### Key Formats
- 🔑 **Binary format** (recommended): 32-byte file
- 🔠 **Base85 format**: 44 character printable string

### Key Rotation
```bash
# Generate new key
python -c "import os; print(os.urandom(32))" > key.txt
```

## Security Features

1. **Cryptographic Protections**
   - 256-bit AES keys
   - 96-bit random nonce
   - 128-bit authentication tag
   - PBKDF2 key stretching (when using password input)

2. **Code Protection**
   - Bytecode compilation
   - Random identifier generation
   - Control flow obfuscation
   - Anti-debugging techniques

3. **Operational Security**
   - Separate key storage
   - Memory-safe decryption
   - Zero temporary files

## Limitations

- ❗ Not suitable for public client-side distribution
- 🔄 Requires re-obfuscation after code changes
- ⚠️ Loses original line numbers in stack traces

## License

This project is licensed under the [Anti-996 License](https://github.com/996icu/996.ICU/blob/master/LICENSE) - Use for ethical purposes only.

---

> **Warning**  
> This provides technical protection, not absolute security.  
> Always combine with legal measures for IP protection.
```

This README provides:
1. Clear installation/usage instructions
2. Technical specifications for security teams
3. Operational guidelines for developers
4. Realistic security expectations
5. Ethical use considerations

