#!/usr/bin/env python3
"""
Automated Comment Translation Script for Q-TLS Project
Translates all code comments from English to Korean while preserving code logic
"""

import re
import os
from pathlib import Path

# Translation dictionary for technical terms and common phrases
TRANSLATIONS = {
    # Project and general terms
    "Quantum-Resistant Transport Security Layer": "양자 내성 전송 보안 계층",
    "Post-Quantum Cryptography": "양자 후 암호학",
    "Post-quantum": "양자 후",
    "quantum-resistant": "양자 내성",
    "Quantum-resistant": "양자 내성",

    # Library and implementation terms
    "Main API header": "메인 API 헤더",
    "API header": "API 헤더",
    "implementation": "구현",
    "Implementation": "구현",
    "providing": "제공하는",
    "hybrid cryptography": "하이브리드 암호화",
    "classical": "고전",
    "Classical": "고전",

    # Cryptographic algorithms
    "KYBER1024": "KYBER1024",
    "KYBER": "KYBER",
    "ML-KEM-1024": "ML-KEM-1024",
    "DILITHIUM3": "DILITHIUM3",
    "DILITHIUM": "DILITHIUM",
    "ML-DSA-65": "ML-DSA-65",
   "key encapsulation": "키 캡슐화",
    "Key encapsulation": "키 캡슐화",
    "digital signatures": "디지털 서명",
    "Digital signatures": "디지털 서명",
    "key exchange": "키 교환",
    "Key exchange": "키 교환",
    "signature": "서명",
    "Signature": "서명",

    # Cryptographic operations
    "encapsulation": "캡슐화",
    "Encapsulation": "캡슐화",
    "decapsulation": "역캡슐화",
    "Decapsulation": "역캡슐화",
    "encryption": "암호화",
    "Encryption": "암호화",
    "decryption": "복호화",
    "Decryption": "복호화",
    "signing": "서명",
    "Signing": "서명",
    "verification": "검증",
    "Verification": "검증",
    "key generation": "키 생성",
    "Key generation": "키 생성",
    "key derivation": "키 유도",
    "Key derivation": "키 유도",

    # Security and protocols
    "TLS": "TLS",
    "handshake": "핸드셰이크",
    "Handshake": "핸드셰이크",
    "certificate": "인증서",
    "Certificate": "인증서",
    "verification": "검증",
    "authentication": "인증",
    "Authentication": "인증",
    "mutual TLS": "상호 TLS",
    "Mutual TLS": "상호 TLS",

    # Key and certificate terms
    "public key": "공개 키",
    "Public key": "공개 키",
    "private key": "개인 키",
    "Private key": "개인 키",
    "secret key": "비밀 키",
    "Secret key": "비밀 키",
    "shared secret": "공유 비밀",
    "Shared secret": "공유 비밀",
    "master secret": "마스터 비밀",
    "Master secret": "마스터 비밀",
    "session key": "세션 키",
    "Session key": "세션 키",
    "ciphertext": "암호문",
    "Ciphertext": "암호문",
    "plaintext": "평문",
    "Plaintext": "평문",

    # Data structures and types
    "structure": "구조체",
    "Structure": "구조체",
    "context": "컨텍스트",
    "Context": "컨텍스트",
    "connection": "연결",
    "Connection": "연결",
    "session": "세션",
    "Session": "세션",
    "buffer": "버퍼",
    "Buffer": "버퍼",

    # Operations and functions
    "Create": "생성",
    "create": "생성",
    "Free": "해제",
    "free": "해제",
    "Initialize": "초기화",
    "initialize": "초기화",
    "Cleanup": "정리",
    "cleanup": "정리",
    "Load": "로드",
    "load": "로드",
    "Set": "설정",
    "set": "설정",
    "Get": "가져오기",
    "get": "가져오기",
    "Read": "읽기",
    "read": "읽기",
    "Write": "쓰기",
    "write": "쓰기",
    "Send": "전송",
    "send": "전송",
    "Receive": "수신",
    "receive": "수신",
    "Accept": "수락",
    "accept": "수락",
    "Connect": "연결",
    "connect": "연결",
    "Shutdown": "종료",
    "shutdown": "종료",
    "Close": "닫기",
    "close": "닫기",

    # Error and status terms
    "Error": "오류",
    "error": "오류",
    "Success": "성공",
    "success": "성공",
    "Failed": "실패",
    "failed": "실패",
    "Failure": "실패",
    "failure": "실패",
    "Invalid": "유효하지 않음",
    "invalid": "유효하지 않음",
    "Null pointer": "널 포인터",
    "null pointer": "널 포인터",

    # Configuration and options
    "Configuration": "구성",
    "configuration": "구성",
    "Options": "옵션",
    "options": "옵션",
    "Settings": "설정",
    "settings": "설정",
    "Parameters": "매개변수",
    "parameters": "매개변수",
    "mode": "모드",
    "Mode": "모드",
    "client mode": "클라이언트 모드",
    "Client mode": "클라이언트 모드",
    "server mode": "서버 모드",
    "Server mode": "서버 모드",

    # HSM and hardware
    "HSM": "HSM",
    "Luna HSM": "Luna HSM",
    "PKCS#11": "PKCS#11",
    "hardware": "하드웨어",
    "Hardware": "하드웨어",
    "token": "토큰",
    "Token": "토큰",

    # FIPS and security standards
    "FIPS": "FIPS",
    "FIPS 140-2": "FIPS 140-2",
    "NIST": "NIST",
    "standardized": "표준화된",
    "Standardized": "표준화된",

    # File and I/O
    "file": "파일",
    "File": "파일",
    "path": "경로",
    "Path": "경로",
    "directory": "디렉터리",
    "Directory": "디렉터리",
    "descriptor": "디스크립터",
    "Descriptor": "디스크립터",

    # Network and protocol
    "network": "네트워크",
    "Network": "네트워크",
    "socket": "소켓",
    "Socket": "소켓",
    "protocol": "프로토콜",
    "Protocol": "프로토콜",
    "version": "버전",
    "Version": "버전",
    "cipher suite": "암호 스위트",
    "Cipher suite": "암호 스위트",

    # Data types and sizes
    "bytes": "바이트",
    "Bytes": "바이트",
    "length": "길이",
    "Length": "길이",
    "size": "크기",
    "Size": "크기",
    "maximum": "최대",
    "Maximum": "최대",
    "minimum": "최소",
    "Minimum": "최소",

    # Common phrases
    "Returns": "반환",
    "returns": "반환",
    "on error": "오류 시",
    "On error": "오류 시",
    "on success": "성공 시",
    "On success": "성공 시",
    "if successful": "성공하면",
    "If successful": "성공하면",
    "otherwise": "그렇지 않으면",
    "Otherwise": "그렇지 않으면",
    "or": "또는",
    "and": "및",
    "with": "~와 함께",
    "from": "~로부터",
    "to": "~로",
    "for": "~을 위한",
    "using": "~을 사용하여",
    "via": "~을 통해",

    # Security levels
    "security": "보안",
    "Security": "보안",
    "Level": "수준",
    "level": "수준",
    "highest security": "최고 보안",
    "Highest security": "최고 보안",
    "secure": "보안",
    "Secure": "보안",

    # Specific terms
    "library": "라이브러리",
    "Library": "라이브러리",
    "module": "모듈",
    "Module": "모듈",
    "wrapper": "래퍼",
    "Wrapper": "래퍼",
    "binding": "바인딩",
    "Binding": "바인딩",
    "adapter": "어댑터",
    "Adapter": "어댑터",
    "plugin": "플러그인",
    "Plugin": "플러그인",
    "provider": "프로바이더",
    "Provider": "프로바이더",
    "backend": "백엔드",
    "Backend": "백엔드",

    # Example and usage
    "Example": "예제",
    "example": "예제",
    "Usage": "사용법",
    "usage": "사용법",
    "Features": "기능",
    "features": "기능",

    # Specific Q-TLS terms
    "hybrid mode": "하이브리드 모드",
    "Hybrid mode": "하이브리드 모드",
    "defense-in-depth": "심층 방어",
    "Defense-in-depth": "심층 방어",
    "forward declaration": "전방 선언",
    "Forward declaration": "전방 선언",
    "constant-time": "상수 시간",
    "Constant-time": "상수 시간",

    # Programming specific
    "Validate": "검증",
    "validate": "검증",
    "input": "입력",
    "Input": "입력",
    "output": "출력",
    "Output": "출력",
    "argument": "인자",
    "Argument": "인자",
    "callback": "콜백",
    "Callback": "콜백",
    "pointer": "포인터",
    "Pointer": "포인터",
    "handle": "핸들",
    "Handle": "핸들",
}

# Comprehensive translation patterns
def translate_comment_text(text):
    """Translate comment text using dictionary and patterns"""
    result = text

    # Apply dictionary translations (longest first to avoid partial matches)
    for en, ko in sorted(TRANSLATIONS.items(), key=lambda x: len(x[0]), reverse=True):
        result = result.replace(en, ko)

    # Additional pattern-based translations
    # "X or Y" patterns
    result = re.sub(r'(\w+)\s+또는\s+(\w+)', r'\1 또는 \2', result)

    # "if X" patterns
    result = re.sub(r'if\s+([^,\.]+)', r'\1인 경우', result)

    # "must be" patterns
    result = re.sub(r'must\s+be', r'~이어야 함', result)

    # "can be" patterns
    result = re.sub(r'can\s+be', r'~일 수 있음', result)

    return result

def translate_c_comments(content):
    """Translate C/C++ style comments"""
    def replace_multi_line(match):
        lines = match.group(0).split('\n')
        translated_lines = []
        for line in lines:
            # Keep comment markers
            if line.strip().startswith('/*') or line.strip().startswith('*'):
                prefix = line[:line.find('*') + 1]
                text = line[line.find('*') + 1:].lstrip()
                if text and not text.startswith('/'):
                    translated_lines.append(prefix + ' ' + translate_comment_text(text))
                else:
                    translated_lines.append(line)
            else:
                translated_lines.append(line)
        return '\n'.join(translated_lines)

    def replace_single_line(match):
        prefix = match.group(1)
        text = match.group(2)
        return prefix + translate_comment_text(text)

    # Multi-line comments
    content = re.sub(r'/\*.*?\*/', replace_multi_line, content, flags=re.DOTALL)

    # Single-line comments
    content = re.sub(r'(//\s*)(.*)', replace_single_line, content)

    return content

def translate_python_comments(content):
    """Translate Python comments and docstrings"""
    def replace_docstring(match):
        quote = match.group(1)
        text = match.group(2)
        return quote + translate_comment_text(text) + quote

    def replace_comment(match):
        prefix = match.group(1)
        text = match.group(2)
        return prefix + translate_comment_text(text)

    # Docstrings (triple quotes)
    content = re.sub(r'(""")(.*?)(""")', replace_docstring, content, flags=re.DOTALL)
    content = re.sub(r"(''')"(.*?)(''')", replace_docstring, content, flags=re.DOTALL)

    # Single-line comments
    content = re.sub(r'(#\s*)(.*)', replace_comment, content)

    return content

def translate_java_comments(content):
    """Translate Java/JavaScript comments"""
    return translate_c_comments(content)

def translate_lua_comments(content):
    """Translate Lua comments"""
    def replace_multi_line(match):
        text = match.group(1)
        return '--[[' + translate_comment_text(text) + ']]'

    def replace_single_line(match):
        prefix = match.group(1)
        text = match.group(2)
        return prefix + translate_comment_text(text)

    # Multi-line comments
    content = re.sub(r'--\[\[(.*?)\]\]', replace_multi_line, content, flags=re.DOTALL)

    # Single-line comments
    content = re.sub(r'(--\s*)(.*)', replace_single_line, content)

    return content

def translate_go_comments(content):
    """Translate Go comments"""
    return translate_c_comments(content)

def translate_file(file_path):
    """Translate comments in a file based on its extension"""
    print(f"Processing: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    # Determine file type and apply appropriate translation
    ext = os.path.splitext(file_path)[1].lower()

    if ext in ['.h', '.c', '.cpp', '.cc']:
        content = translate_c_comments(content)
    elif ext == '.py':
        content = translate_python_comments(content)
    elif ext in ['.java', '.js']:
        content = translate_java_comments(content)
    elif ext == '.lua':
        content = translate_lua_comments(content)
    elif ext == '.go':
        content = translate_go_comments(content)
    else:
        print(f"  Skipping unknown file type: {ext}")
        return False

    # Only write if content changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  ✓ Translated")
        return True
    else:
        print(f"  - No changes needed")
        return False

def main():
    """Main translation function"""
    base_path = Path('/home/user/QSIGN/Q-TLS')

    files_to_translate = [
        # C/C++ headers and sources
        'include/qtls/qtls.h',
        'src/crypto/pqc_crypto.c',
        'src/protocol/handshake.c',
        'src/server/qtls_server.c',
        'src/client/qtls_client.c',

        # Language bindings
        'bindings/python/qtls.py',
        'bindings/nodejs/qtls.js',
        'bindings/go/qtls.go',

        # Adapters
        'adapters/apisix/qtls-plugin.lua',
        'adapters/keycloak/QTLSProvider.java',
        'adapters/vault/qtls_backend.go',
        'adapters/vault/qtls_hsm.go',
        'adapters/vault/path_keys.go',
        'adapters/vault/path_operations.go',
        'adapters/vault/path_config.go',
        'adapters/vault/main.go',
    ]

    translated_count = 0
    skipped_count = 0

    print("=" * 70)
    print("Q-TLS Comment Translation Script")
    print("Converting English comments to Korean")
    print("=" * 70)
    print()

    for file_rel_path in files_to_translate:
        file_path = base_path / file_rel_path
        if file_path.exists():
            if translate_file(str(file_path)):
                translated_count += 1
            else:
                skipped_count += 1
        else:
            print(f"Warning: File not found: {file_path}")
            skipped_count += 1

    print()
    print("=" * 70)
    print(f"Translation complete!")
    print(f"  Files translated: {translated_count}")
    print(f"  Files skipped: {skipped_count}")
    print("=" * 70)

if __name__ == '__main__':
    main()
