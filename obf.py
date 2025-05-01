import sys
import os
import random
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import marshal

def generate_random_name(length=12):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
    return ''.join(random.choice(chars) for _ in range(length))

def obfuscate(input_file: str, output_file: str, key_file: str = None):
    with open(input_file, 'r', encoding='utf-8') as f:
        code = marshal.dumps(compile(f.read(), '<string>', 'exec'))
    
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, code, None)
    
    vars = {
        'enc_data': generate_random_name(),
        'key_data': generate_random_name(),
        'aesgcm': generate_random_name(),
        'marshal_mod': generate_random_name(),
        'base64_mod': generate_random_name(),
        'key_input': generate_random_name(),
        'nonce': generate_random_name(),
        'cipher': generate_random_name(),
        'exit_func': generate_random_name(),
        'input_func': generate_random_name(),
        'print_func': generate_random_name(),
        'open_func': generate_random_name(),
    }
    
    template = f"""
from builtins import exec, input as {vars['input_func']}, print as {vars['print_func']}, open as {vars['open_func']}, exit as {vars['exit_func']}
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as {vars['aesgcm']}
import marshal as {vars['marshal_mod']}
import base64 as {vars['base64_mod']}

{vars['print_func']}("🔒 Secure System Initialization")
{vars['enc_data']} = {base64.b85encode(nonce + ciphertext).decode()!r}

def {vars['key_input']}():
    try:
        with {vars['open_func']}("{key_file if key_file else 'key.bin'}", "rb") as f:
            return f.read()
    except:
        {vars['print_func']}("⚠️ Enter decryption key (base64 encoded):")
        return {vars['base64_mod']}.b85decode({vars['input_func']}().encode())

{vars['key_data']} = {vars['key_input']}()
{vars['print_func']}("🛡️  Decrypting payload...")

try:
    {vars['nonce']} = {vars['base64_mod']}.b85decode({vars['enc_data']})[:12]
    {vars['cipher']} = {vars['base64_mod']}.b85decode({vars['enc_data']})[12:]
    decrypted = {vars['aesgcm']}({vars['key_data']}).decrypt({vars['nonce']}, {vars['cipher']}, None)
    exec({vars['marshal_mod']}.loads(decrypted))
except Exception as e:
    {vars['print_func']}(f"💀 Critical error: {{e}}")
    {vars['exit_func']}(1)
"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(template)
    
    if key_file:
        with open(key_file, 'wb') as f:
            f.write(key)
    else:
        print(f"🔑 EMERGENCY KEY:\n{base64.b85encode(key).decode()}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python obfuscator.py <input.py> <output.py> [keyfile]")
        sys.exit(1)
    
    obfuscate(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    print(f"✅ Obfuscation complete: {sys.argv[2]}")