#!/usr/bin/env python3
from __future__ import annotations
import sys, os, time, json, argparse, hashlib, base64
from typing import Optional

# add repo root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import requests
from pppoker.api import (
    PPPokerAPI,
    compute_crypto_password,
    encrypt_password_exact,
    mmddhhmmss_from_epoch_beijing,
    _normalize_imei,
)


def _xxtea_encrypt_blocks(v: list[int], k: list[int]) -> list[int]:
    DELTA = 0x9E3779B9
    n = len(v)
    if n < 2:
        return v
    z = v[n - 1]
    s = 0
    q = 6 + 52 // n
    for _ in range(q):
        s = (s + DELTA) & 0xFFFFFFFF
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + mx) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[((n - 1) & 3) ^ e] ^ z))
        v[n - 1] = (v[n - 1] + mx) & 0xFFFFFFFF
        z = v[n - 1]
    return v


def _to_u32_le_blocks(b: bytes) -> list[int]:
    assert len(b) % 4 == 0
    return [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]


def _from_u32_le_blocks(v: list[int]) -> bytes:
    return b''.join((x & 0xFFFFFFFF).to_bytes(4, 'little') for x in v)

def _to_u32_be_blocks(b: bytes) -> list[int]:
    assert len(b) % 4 == 0
    return [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)]

def _from_u32_be_blocks(v: list[int]) -> bytes:
    return b''.join((x & 0xFFFFFFFF).to_bytes(4, 'big') for x in v)


def encrypt_any_field_exact(value: str, epoch: int) -> str:
    """Encrypt arbitrary ASCII/UTF-8 string like PPPoker password encryption.
    - key: (mmddhhmmss(Beijing(epoch)) + 'd56590')
    - payload: utf-8(value) + len(value).to_bytes(4, 'little')
    - cipher: XXTEA over u32 LE blocks
    - output: base64
    """
    key16 = (mmddhhmmss_from_epoch_beijing(epoch) + 'd56590').encode('ascii')
    pt = value.encode('utf-8')
    payload = pt + len(pt).to_bytes(4, 'little')
    # pad to multiple of 4 bytes
    if len(payload) % 4 != 0:
        pad = 4 - (len(payload) % 4)
        payload += b'\x00' * pad
    v = _to_u32_le_blocks(payload)
    k = _to_u32_le_blocks(key16)
    ct = _xxtea_encrypt_blocks(v, k)
    out = _from_u32_le_blocks(ct)
    return base64.b64encode(out).decode('ascii')


# AES/3DES ECB helpers via cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except Exception:
    Cipher = None  # type: ignore

def _pkcs7_pad(b: bytes, block: int = 16) -> bytes:
    pad = block - (len(b) % block)
    return b + bytes([pad]) * pad

def _aes_ecb_b64(pt: bytes, key: bytes) -> Optional[str]:
    if Cipher is None:
        return None
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(_pkcs7_pad(pt, 16)) + enc.finalize()
    import base64 as _b64
    return _b64.b64encode(ct).decode('ascii')

def _aes_ecb_b64_payload(payload: bytes, key: bytes) -> Optional[str]:
    if Cipher is None:
        return None
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(_pkcs7_pad(payload, 16)) + enc.finalize()
    import base64 as _b64
    return _b64.b64encode(ct).decode('ascii')

def _des3_ecb_b64_payload(payload: bytes, key: bytes) -> Optional[str]:
    if Cipher is None:
        return None
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(_pkcs7_pad(payload, 8)) + enc.finalize()
    import base64 as _b64
    return _b64.b64encode(ct).decode('ascii')

# XXTEA payload variants
def _xxtea_b64_with_payload(payload: bytes, key16: bytes) -> str:
    # pad to multiple of 4 bytes
    if len(payload) % 4 != 0:
        payload += b'\x00' * (4 - (len(payload) % 4))
    v = _to_u32_le_blocks(payload)
    k = _to_u32_le_blocks(key16)
    return base64.b64encode(_from_u32_le_blocks(_xxtea_encrypt_blocks(v, k))).decode('ascii')

def _xxtea_b64_with_payload_be(payload: bytes, key16: bytes) -> str:
    if len(payload) % 4 != 0:
        payload += b'\x00' * (4 - (len(payload) % 4))
    v = _to_u32_be_blocks(payload)
    k = _to_u32_be_blocks(key16)
    return base64.b64encode(_from_u32_be_blocks(_xxtea_encrypt_blocks(v, k))).decode('ascii')

def do_register_probe(username: str, password: str, device_id: str, proxy: Optional[str], scheme: str = 'auto', clientvar: Optional[str] = None, t_epoch_override: Optional[int] = None) -> dict:
    api = PPPokerAPI(proxy=proxy)
    if clientvar:
        api.client_version = clientvar
        api._version_fetched = True
    else:
        # fetch version early
        try:
            api.fetch_server_version()
        except Exception:
            pass
    sess = requests.Session()
    sess.trust_env = False  # ignore OS proxy vars unless explicitly provided
    if proxy:
        sess.proxies = api.proxies or {}
    sess.verify = False
    headers = {
        'User-Agent': 'UnityPlayer/2022.3.43f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
        'Accept': '*/*',
        'Accept-Encoding': 'deflate, gzip',
        'X-Unity-Version': '2022.3.43f1',
    }
    # prefetch root to set cookies (aliyungf_tc)
    try:
        sess.get('https://www.pppoker.club/', headers=headers, timeout=10)
    except Exception:
        pass
    schemes = []
    if scheme == 'auto':
        scheme_names = [
            'dmd5raw','md5raw','md5raw+t10','md5raw+epoch','dmd5raw+t10','dmd5raw+epoch','doublemd5','md5','plain','plain@epochkey',
            'xxtea_no_len','xxtea_len_be','xxtea_len_first','xxtea_len_be_first','xxtea_md5key_t10','xxtea_md5key_epoch','xxtea_be_blocks','xxtea_be_blocks_len_be',
            'aes_t10','aes_epoch','aes_imei','aes_t10_ascii','aes_epoch_ascii','aes_t10_ascii+len','aes_epoch_ascii+len','aes_epoch+len','aes_t10+len',
            'des3_t10_ascii','des3_epoch_ascii','des3_t10_ascii+len','des3_epoch_ascii+len',
            'sha1_t_le','sha1_t_be','sha1_t10_le','sha1_t10_be',
            'sha1_salt_t_le','sha1_salt_t_be','sha1_salt_t10_le','sha1_salt_t10_be',
            'sha1_username_imei_t_le','sha1_username_imei_t_be','sha1_username_clientver_t_le','sha1_username_clientver_t_be',
            'hex','b64']
    elif scheme == 'doublemd5':
        scheme_names = ['doublemd5']
    elif scheme == 'md5':
        scheme_names = ['md5']
    elif scheme == 'dmd5raw':
        scheme_names = ['dmd5raw']
    elif scheme == 'md5raw':
        scheme_names = ['md5raw']
    elif scheme == 'md5raw+t10':
        scheme_names = ['md5raw+t10']
    elif scheme == 'md5raw+epoch':
        scheme_names = ['md5raw+epoch']
    elif scheme == 'plain@epochkey':
        scheme_names = ['plain@epochkey']
    elif scheme == 'aes_t10':
        scheme_names = ['aes_t10']
    elif scheme == 'aes_epoch':
        scheme_names = ['aes_epoch']
    elif scheme == 'aes_imei':
        scheme_names = ['aes_imei']
    elif scheme == 'xxtea_no_len':
        scheme_names = ['xxtea_no_len']
    elif scheme == 'xxtea_len_be':
        scheme_names = ['xxtea_len_be']
    elif scheme == 'xxtea_len_first':
        scheme_names = ['xxtea_len_first']
    elif scheme == 'xxtea_len_be_first':
        scheme_names = ['xxtea_len_be_first']
    elif scheme == 'xxtea_md5key_t10':
        scheme_names = ['xxtea_md5key_t10']
    elif scheme == 'xxtea_md5key_epoch':
        scheme_names = ['xxtea_md5key_epoch']
    elif scheme == 'xxtea_be_blocks':
        scheme_names = ['xxtea_be_blocks']
    elif scheme == 'xxtea_be_blocks_len_be':
        scheme_names = ['xxtea_be_blocks_len_be']
    elif scheme == 'aes_t10_ascii':
        scheme_names = ['aes_t10_ascii']
    elif scheme == 'aes_epoch_ascii':
        scheme_names = ['aes_epoch_ascii']
    elif scheme == 'aes_t10_ascii+len':
        scheme_names = ['aes_t10_ascii+len']
    elif scheme == 'aes_epoch_ascii+len':
        scheme_names = ['aes_epoch_ascii+len']
    elif scheme == 'aes_epoch+len':
        scheme_names = ['aes_epoch+len']
    elif scheme == 'aes_t10+len':
        scheme_names = ['aes_t10+len']
    elif scheme == 'des3_t10_ascii':
        scheme_names = ['des3_t10_ascii']
    elif scheme == 'des3_epoch_ascii':
        scheme_names = ['des3_epoch_ascii']
    elif scheme == 'des3_t10_ascii+len':
        scheme_names = ['des3_t10_ascii+len']
    elif scheme == 'des3_epoch_ascii+len':
        scheme_names = ['des3_epoch_ascii+len']
    elif scheme == 'sha1_t_le':
        scheme_names = ['sha1_t_le']
    elif scheme == 'sha1_t_be':
        scheme_names = ['sha1_t_be']
    elif scheme == 'sha1_t10_le':
        scheme_names = ['sha1_t10_le']
    elif scheme == 'sha1_t10_be':
        scheme_names = ['sha1_t10_be']
    elif scheme == 'sha1_salt_t_le':
        scheme_names = ['sha1_salt_t_le']
    elif scheme == 'sha1_salt_t_be':
        scheme_names = ['sha1_salt_t_be']
    elif scheme == 'sha1_salt_t10_le':
        scheme_names = ['sha1_salt_t10_le']
    elif scheme == 'sha1_salt_t10_be':
        scheme_names = ['sha1_salt_t10_be']
    elif scheme == 'sha1_username_imei_t_le':
        scheme_names = ['sha1_username_imei_t_le']
    elif scheme == 'sha1_username_imei_t_be':
        scheme_names = ['sha1_username_imei_t_be']
    elif scheme == 'sha1_username_clientver_t_le':
        scheme_names = ['sha1_username_clientver_t_le']
    elif scheme == 'sha1_username_clientver_t_be':
        scheme_names = ['sha1_username_clientver_t_be']
    elif scheme == 'dmd5raw+t10':
        scheme_names = ['dmd5raw+t10']
    elif scheme == 'dmd5raw+epoch':
        scheme_names = ['dmd5raw+epoch']
    else:
        scheme_names = ['plain']

    url = 'https://www.pppoker.club/poker/api/register.php'
    import base64 as _b64
    SALTS = ['d56590','pppoker','poker','globle','WindowsPlayer']
    for name in scheme_names:
        # fresh timestamp and imei per request
        t_epoch = int(t_epoch_override or int(time.time()))
        enc_pwd = encrypt_password_exact(compute_crypto_password(password), t_epoch)
        # generate IMEI once per attempt and allow using it in enc_user
        import uuid as _uuid
        imei_seed = str(_uuid.uuid4())
        imei_val = _normalize_imei(imei_seed, username)
        # compute enc_user for this attempt using same t
        t10 = mmddhhmmss_from_epoch_beijing(t_epoch)
        enc_user_variants = []  # list of tuples (label, value)
        if name == 'dmd5raw':
            import base64 as _b64
            inner = hashlib.md5(username.encode('utf-8')).digest()
            outer = hashlib.md5(inner).digest()
            enc_user = _b64.b64encode(outer).decode('ascii')
        elif name == 'dmd5raw+t10':
            import base64 as _b64
            inner = hashlib.md5((username + t10).encode('utf-8')).digest()
            outer = hashlib.md5(inner).digest()
            enc_user = _b64.b64encode(outer).decode('ascii')
        elif name == 'dmd5raw+epoch':
            import base64 as _b64
            inner = hashlib.md5((username + str(t_epoch)).encode('utf-8')).digest()
            outer = hashlib.md5(inner).digest()
            enc_user = _b64.b64encode(outer).decode('ascii')
        elif name == 'md5raw':
            import base64 as _b64
            enc_user = _b64.b64encode(hashlib.md5(username.encode('utf-8')).digest()).decode('ascii')
        elif name == 'md5raw+t10':
            import base64 as _b64
            enc_user = _b64.b64encode(hashlib.md5((username + t10).encode('utf-8')).digest()).decode('ascii')
        elif name == 'md5raw+epoch':
            import base64 as _b64
            enc_user = _b64.b64encode(hashlib.md5((username + str(t_epoch)).encode('utf-8')).digest()).decode('ascii')
        elif name == 'doublemd5':
            enc_user = encrypt_any_field_exact(hashlib.md5(hashlib.md5(username.encode('utf-8')).hexdigest().encode('ascii')).hexdigest(), t_epoch)
        elif name == 'md5':
            enc_user = encrypt_any_field_exact(hashlib.md5(username.encode('utf-8')).hexdigest(), t_epoch)
        elif name == 'hex':
            enc_user = encrypt_any_field_exact(username.encode('utf-8').hex(), t_epoch)
        elif name == 'b64':
            enc_user = encrypt_any_field_exact(_b64.b64encode(username.encode('utf-8')).decode('ascii'), t_epoch)
        elif name == 'aes_t10':
            import hashlib as _hh
            key = _hh.md5((t10 + 'd56590').encode('ascii')).digest()
            enc_user = _aes_ecb_b64(username.encode('utf-8'), key) or ''
        elif name == 'aes_t10+len':
            import hashlib as _hh
            key = _hh.md5((t10 + 'd56590').encode('ascii')).digest()
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _aes_ecb_b64_payload(payload, key) or ''
        elif name == 'aes_epoch':
            import hashlib as _hh
            key = _hh.md5((str(t_epoch) + 'd56590').encode('ascii')).digest()
            enc_user = _aes_ecb_b64(username.encode('utf-8'), key) or ''
        elif name == 'aes_epoch+len':
            import hashlib as _hh
            key = _hh.md5((str(t_epoch) + 'd56590').encode('ascii')).digest()
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _aes_ecb_b64_payload(payload, key) or ''
        elif name == 'aes_t10_ascii':
            key = (t10 + 'd56590').encode('ascii')
            enc_user = _aes_ecb_b64(username.encode('utf-8'), key) or ''
        elif name == 'aes_t10_ascii+len':
            key = (t10 + 'd56590').encode('ascii')
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _aes_ecb_b64_payload(payload, key) or ''
        elif name == 'aes_epoch_ascii':
            key = (str(t_epoch) + 'd56590').encode('ascii')
            enc_user = _aes_ecb_b64(username.encode('utf-8'), key) or ''
        elif name == 'aes_epoch_ascii+len':
            key = (str(t_epoch) + 'd56590').encode('ascii')
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _aes_ecb_b64_payload(payload, key) or ''
        elif name == 'aes_imei':
            import hashlib as _hh
            # derive imei same as api normalization
            import uuid as _uuid
            # If device_id provided, normalize; else synthesize
            imei_source = device_id or username
            imei_norm = _normalize_imei(imei_source, username)
            key = _hh.md5((imei_norm[:16]).encode('ascii')).digest()
            enc_user = _aes_ecb_b64(username.encode('utf-8'), key) or ''
        elif name == 'des3_t10_ascii':
            key = (t10 + 'd56590').encode('ascii')  # 16 bytes -> 2-key 3DES
            enc_user = _des3_ecb_b64_payload(username.encode('utf-8'), key) or ''
        elif name == 'des3_epoch_ascii':
            key = (str(t_epoch) + 'd56590').encode('ascii')
            enc_user = _des3_ecb_b64_payload(username.encode('utf-8'), key) or ''
        elif name == 'des3_t10_ascii+len':
            key = (t10 + 'd56590').encode('ascii')
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _des3_ecb_b64_payload(payload, key) or ''
        elif name == 'des3_epoch_ascii+len':
            key = (str(t_epoch) + 'd56590').encode('ascii')
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _des3_ecb_b64_payload(payload, key) or ''
        elif name == 'sha1_t_le':
            import base64 as _b64
            import hashlib as _hh
            payload = _hh.sha1(username.encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'little', signed=False)
            enc_user = _b64.b64encode(payload).decode('ascii')
        elif name == 'sha1_t_be':
            import base64 as _b64
            import hashlib as _hh
            payload = _hh.sha1(username.encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'big', signed=False)
            enc_user = _b64.b64encode(payload).decode('ascii')
        elif name == 'sha1_t10_le':
            import base64 as _b64
            import hashlib as _hh
            payload = _hh.sha1(username.encode('utf-8')).digest() + int(t10).to_bytes(4, 'little', signed=False)
            enc_user = _b64.b64encode(payload).decode('ascii')
        elif name == 'sha1_t10_be':
            import base64 as _b64
            import hashlib as _hh
            payload = _hh.sha1(username.encode('utf-8')).digest() + int(t10).to_bytes(4, 'big', signed=False)
            enc_user = _b64.b64encode(payload).decode('ascii')
        elif name == 'xxtea_no_len':
            key16 = (t10 + 'd56590').encode('ascii')
            payload = username.encode('utf-8')
            enc_user = _xxtea_b64_with_payload(payload, key16)
        elif name == 'xxtea_len_be':
            key16 = (t10 + 'd56590').encode('ascii')
            ln = len(username.encode('utf-8')).to_bytes(4, 'big')
            payload = username.encode('utf-8') + ln
            enc_user = _xxtea_b64_with_payload(payload, key16)
        elif name == 'xxtea_len_first':
            key16 = (t10 + 'd56590').encode('ascii')
            ln = len(username.encode('utf-8')).to_bytes(4, 'little')
            payload = ln + username.encode('utf-8')
            enc_user = _xxtea_b64_with_payload(payload, key16)
        elif name == 'xxtea_len_be_first':
            key16 = (t10 + 'd56590').encode('ascii')
            ln = len(username.encode('utf-8')).to_bytes(4, 'big')
            payload = ln + username.encode('utf-8')
            enc_user = _xxtea_b64_with_payload(payload, key16)
        elif name == 'xxtea_md5key_t10':
            import hashlib as _hh
            key16 = _hh.md5((t10 + 'd56590').encode('ascii')).digest()
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _xxtea_b64_with_payload(payload, key16)
        elif name == 'xxtea_md5key_epoch':
            import hashlib as _hh
            key16 = _hh.md5((str(t_epoch) + 'd56590').encode('ascii')).digest()
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _xxtea_b64_with_payload(payload, key16)
        elif name == 'xxtea_be_blocks':
            key16 = (t10 + 'd56590').encode('ascii')
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'little')
            enc_user = _xxtea_b64_with_payload_be(payload, key16)
        elif name == 'xxtea_be_blocks_len_be':
            key16 = (t10 + 'd56590').encode('ascii')
            payload = username.encode('utf-8') + len(username.encode('utf-8')).to_bytes(4, 'big')
            enc_user = _xxtea_b64_with_payload_be(payload, key16)
        elif name == 'plain@epochkey':
            # same XXTEA but with key seed as str(epoch)+'d56590'
            key16 = (str(t_epoch) + 'd56590').encode('ascii')
            pt = username.encode('utf-8')
            payload = pt + len(pt).to_bytes(4, 'little')
            if len(payload) % 4 != 0:
                payload += b'\x00' * (4 - (len(payload) % 4))
            v = _to_u32_le_blocks(payload)
            k = _to_u32_le_blocks(key16)
            enc_user = _b64.b64encode(_from_u32_le_blocks(_xxtea_encrypt_blocks(v, k))).decode('ascii')
        else:
            enc_user = encrypt_any_field_exact(username, t_epoch)
        # Support multi-candidate schemes
        if name in ('sha1_salt_t_le','sha1_salt_t_be','sha1_salt_t10_le','sha1_salt_t10_be'):
            import base64 as _b64
            import hashlib as _hh
            for s in SALTS:
                if name == 'sha1_salt_t_le':
                    payload = _hh.sha1((username + s).encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'little')
                elif name == 'sha1_salt_t_be':
                    payload = _hh.sha1((username + s).encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'big')
                elif name == 'sha1_salt_t10_le':
                    payload = _hh.sha1((username + s).encode('utf-8')).digest() + int(t10).to_bytes(4, 'little')
                else:
                    payload = _hh.sha1((username + s).encode('utf-8')).digest() + int(t10).to_bytes(4, 'big')
                enc_user_variants.append((f"{name}:{s}", _b64.b64encode(payload).decode('ascii')))
        elif name in ('sha1_username_imei_t_le','sha1_username_imei_t_be','sha1_username_clientver_t_le','sha1_username_clientver_t_be'):
            import base64 as _b64
            import hashlib as _hh
            if name.startswith('sha1_username_imei'):
                seed = imei_val
            else:
                seed = (api.client_version or '')
            # combine username + seed, then append time
            if name.endswith('_t_le'):
                payload = _hh.sha1((username + seed).encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'little')
            else:
                payload = _hh.sha1((username + seed).encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'big')
            enc_user_variants.append((name, _b64.b64encode(payload).decode('ascii')))
        else:
            enc_user_variants.append((name, enc_user))
        for label, enc_user_val in enc_user_variants:
            params = {
                'username': enc_user_val,
                'password': enc_pwd,
            't': str(t_epoch),
            'distributor': '0',
            'sub_distributor': '0',
            'country': 'RU',
            'appid': 'globle',
            'os': 'WindowsPlayer',
            'imei': imei_val,
            'clientvar': api.client_version,
            'app_type': '1',
        }
            r = sess.get(url, params=params, headers=headers, timeout=20)
            j = r.json()
            code = int(j.get('code', -1)) if isinstance(j, dict) else -999
            print(f"[TRY {label}] code={code}")
            if code == 0:
                return {'scheme': label, 'code': code, 'enc_user': enc_user_val, 'enc_pwd': enc_pwd, 't': t_epoch, 'clientvar': api.client_version, 'imei': imei_val}
    return {'scheme': None, 'code': code, 'clientvar': api.client_version}


def main():
    ap = argparse.ArgumentParser(description='Probe PPPoker register username encryption')
    ap.add_argument('--username', default='childedo')
    ap.add_argument('--password', default='qwe123qwe123')
    ap.add_argument('--device-id', default='')
    ap.add_argument('--proxy', default=None)
    ap.add_argument('--scheme', default='auto', choices=['auto','plain','md5','doublemd5','dmd5raw','md5raw','md5raw+t10','md5raw+epoch','dmd5raw+t10','dmd5raw+epoch','xxtea_no_len','xxtea_len_be','xxtea_len_first','xxtea_len_be_first','aes_t10','aes_epoch','aes_imei','aes_t10_ascii','aes_epoch_ascii','aes_t10_ascii+len','aes_epoch_ascii+len','aes_epoch+len','aes_t10+len','hex','b64'])
    ap.add_argument('--clientvar', default=None)
    ap.add_argument('--imei', default=None, help='override IMEI (40-hex) for print-only variants that use IMEI')
    ap.add_argument('--t-epoch', type=int, default=None, help='override epoch for encryption')
    ap.add_argument('--print-only', action='store_true', help='do not call register; just print enc username variants')
    ap.add_argument('--compare', default=None, help='sample base64 to compare with --print-only')
    args = ap.parse_args()

    if not args.device_id:
        # generate simple seed
        import uuid
        args.device_id = str(uuid.uuid4())

    if args.print_only:
        # show enc variants for provided epoch
        t_epoch = int(args.t_epoch or int(time.time()))
        print('[t]', t_epoch)
        import base64 as _b64
        t10 = mmddhhmmss_from_epoch_beijing(t_epoch)
        cv = (args.clientvar or '').strip()
        # helper for epoch-key variant
        def xxtea_epochkey(s: str) -> str:
            key16 = (str(t_epoch) + 'd56590').encode('ascii')
            pt = s.encode('utf-8')
            payload = pt + len(pt).to_bytes(4, 'little')
            if len(payload) % 4 != 0:
                payload += b'\x00' * (4 - (len(payload) % 4))
            v = _to_u32_le_blocks(payload); k = _to_u32_le_blocks(key16)
            return _b64.b64encode(_from_u32_le_blocks(_xxtea_encrypt_blocks(v, k))).decode('ascii')
        # AES keys derived via MD5 of seed strings
        import hashlib as _hh
        aes_t10_key = _hh.md5((t10 + 'd56590').encode('ascii')).digest()
        aes_epoch_key = _hh.md5((str(t_epoch) + 'd56590').encode('ascii')).digest()
        imei_norm = (args.imei or _normalize_imei(args.device_id, args.username))
        aes_imei_key = _hh.md5((imei_norm[:16]).encode('ascii')).digest()
        # salted MD5 combos
        SALTS = ['d56590','pppoker','poker','globle','WindowsPlayer']
        def b64_md5(s: str) -> str:
            return _b64.b64encode(hashlib.md5(s.encode('utf-8')).digest()).decode('ascii')
        md5c = {}
        for c in SALTS:
            md5c[f'md5raw:{args.username}+{t10}+{c}'] = b64_md5(args.username + t10 + c)
            md5c[f'md5raw:{c}+{args.username}+{t10}'] = b64_md5(c + args.username + t10)
            md5c[f'md5raw:{args.username}+{c}+{t10}'] = b64_md5(args.username + c + t10)
            md5c[f'md5raw:{t10}+{args.username}+{c}'] = b64_md5(t10 + args.username + c)
            md5c[f'md5raw:{c}+{args.username}'] = b64_md5(c + args.username)
            md5c[f'md5raw:{args.username}+{c}'] = b64_md5(args.username + c)
            md5c[f'md5raw:{args.username}+{str(t_epoch)}+{c}'] = b64_md5(args.username + str(t_epoch) + c)
            md5c[f'md5raw:{c}+{args.username}+{str(t_epoch)}'] = b64_md5(c + args.username + str(t_epoch))
        variants = {
            'dmd5raw': _b64.b64encode(hashlib.md5(hashlib.md5(args.username.encode('utf-8')).digest()).digest()).decode('ascii'),
            'dmd5raw+t10': _b64.b64encode(hashlib.md5(hashlib.md5((args.username + t10).encode('utf-8')).digest()).digest()).decode('ascii'),
            'dmd5raw+epoch': _b64.b64encode(hashlib.md5(hashlib.md5((args.username + str(t_epoch)).encode('utf-8')).digest()).digest()).decode('ascii'),
            'md5raw': _b64.b64encode(hashlib.md5(args.username.encode('utf-8')).digest()).decode('ascii'),
            'md5raw+t10': _b64.b64encode(hashlib.md5((args.username + t10).encode('utf-8')).digest()).decode('ascii'),
            'md5raw+epoch': _b64.b64encode(hashlib.md5((args.username + str(t_epoch)).encode('utf-8')).digest()).decode('ascii'),
            'doublemd5': encrypt_any_field_exact(hashlib.md5(hashlib.md5(args.username.encode('utf-8')).hexdigest().encode('ascii')).hexdigest(), t_epoch),
            'md5': encrypt_any_field_exact(hashlib.md5(args.username.encode('utf-8')).hexdigest(), t_epoch),
'plain': encrypt_any_field_exact(args.username, t_epoch),
            'plain@epochkey': xxtea_epochkey(args.username),
            'xxtea_no_len': _xxtea_b64_with_payload(args.username.encode('utf-8'), (t10 + 'd56590').encode('ascii')),
            'xxtea_len_be': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'big'), (t10 + 'd56590').encode('ascii')),
            'xxtea_len_first': _xxtea_b64_with_payload(len(args.username.encode('utf-8')).to_bytes(4, 'little') + args.username.encode('utf-8'), (t10 + 'd56590').encode('ascii')),
'xxtea_len_be_first': _xxtea_b64_with_payload(len(args.username.encode('utf-8')).to_bytes(4, 'big') + args.username.encode('utf-8'), (t10 + 'd56590').encode('ascii')),
            'xxtea_md5key_t10': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), __import__('hashlib').md5((t10 + 'd56590').encode('ascii')).digest()),
'xxtea_md5key_epoch': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), __import__('hashlib').md5((str(t_epoch) + 'd56590').encode('ascii')).digest()),
            'xxtea_be_blocks': _xxtea_b64_with_payload_be(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (t10 + 'd56590').encode('ascii')),
'xxtea_be_blocks_len_be': _xxtea_b64_with_payload_be(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'big'), (t10 + 'd56590').encode('ascii')),
            # XXTEA with alternative key seeds (clientvar/appid/imei6)
            **({ 'xxtea_t10+clientvar': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (t10 + cv).encode('ascii')) } if cv and len(t10 + cv) == 16 else {}),
            'xxtea_t10+clientvar(md5)': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), __import__('hashlib').md5((t10 + cv).encode('ascii')).digest()) if cv else '',
            **({ 'xxtea_epoch+clientvar': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (str(t_epoch) + cv).encode('ascii')) } if cv and len(str(t_epoch) + cv) == 16 else {}),
            'xxtea_epoch+clientvar(md5)': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), __import__('hashlib').md5((str(t_epoch) + cv).encode('ascii')).digest()) if cv else '',
            'xxtea_t10+appid': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (t10 + 'globle').encode('ascii')),
            'xxtea_t10+imei6': _xxtea_b64_with_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (t10 + imei_norm[:6]).encode('ascii')),
            'aes_t10': (_aes_ecb_b64(args.username.encode('utf-8'), aes_t10_key) or ''),
            'aes_epoch': (_aes_ecb_b64(args.username.encode('utf-8'), aes_epoch_key) or ''),
            'aes_t10+len': (_aes_ecb_b64_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), aes_t10_key) or ''),
            'aes_epoch+len': (_aes_ecb_b64_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), aes_epoch_key) or ''),
            'aes_t10_ascii': (_aes_ecb_b64(args.username.encode('utf-8'), (t10 + 'd56590').encode('ascii')) or ''),
            'aes_epoch_ascii': (_aes_ecb_b64(args.username.encode('utf-8'), (str(t_epoch) + 'd56590').encode('ascii')) or ''),
'aes_t10_ascii+len': (_aes_ecb_b64_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (t10 + 'd56590').encode('ascii')) or ''),
'aes_epoch_ascii+len': (_aes_ecb_b64_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (str(t_epoch) + 'd56590').encode('ascii')) or ''),
            'des3_t10_ascii': (_des3_ecb_b64_payload(args.username.encode('utf-8'), (t10 + 'd56590').encode('ascii')) or ''),
            'des3_epoch_ascii': (_des3_ecb_b64_payload(args.username.encode('utf-8'), (str(t_epoch) + 'd56590').encode('ascii')) or ''),
            'des3_t10_ascii+len': (_des3_ecb_b64_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (t10 + 'd56590').encode('ascii')) or ''),
            'des3_epoch_ascii+len': (_des3_ecb_b64_payload(args.username.encode('utf-8') + len(args.username.encode('utf-8')).to_bytes(4, 'little'), (str(t_epoch) + 'd56590').encode('ascii')) or ''),
            'aes_imei': (_aes_ecb_b64(args.username.encode('utf-8'), aes_imei_key) or ''),
            # New 24-byte fixed-size candidates (expect 32-char base64)
            'sha1_t_le': _b64.b64encode(__import__('hashlib').sha1(args.username.encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'little')).decode('ascii'),
            'sha1_t_be': _b64.b64encode(__import__('hashlib').sha1(args.username.encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'big')).decode('ascii'),
            'sha1_t10_le': _b64.b64encode(__import__('hashlib').sha1(args.username.encode('utf-8')).digest() + int(t10).to_bytes(4, 'little')).decode('ascii'),
            'sha1_t10_be': _b64.b64encode(__import__('hashlib').sha1(args.username.encode('utf-8')).digest() + int(t10).to_bytes(4, 'big')).decode('ascii'),
            # Salted variants will be printed per-salt below
        }
        # Print salted SHA1 24-byte candidates as well
        for s in ['d56590','pppoker','poker','globle','WindowsPlayer']:
            variants[f'sha1_salt_t_le:{s}'] = _b64.b64encode(__import__('hashlib').sha1((args.username + s).encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'little')).decode('ascii')
            variants[f'sha1_salt_t_be:{s}'] = _b64.b64encode(__import__('hashlib').sha1((args.username + s).encode('utf-8')).digest() + int(t_epoch).to_bytes(4, 'big')).decode('ascii')
            variants[f'sha1_salt_t10_le:{s}'] = _b64.b64encode(__import__('hashlib').sha1((args.username + s).encode('utf-8')).digest() + int(t10).to_bytes(4, 'little')).decode('ascii')
            variants[f'sha1_salt_t10_be:{s}'] = _b64.b64encode(__import__('hashlib').sha1((args.username + s).encode('utf-8')).digest() + int(t10).to_bytes(4, 'big')).decode('ascii')
        print(json.dumps(variants, indent=2))
        if args.compare:
            found = any(v == args.compare for v in variants.values())
            print('[MATCH]' if found else '[NO MATCH]')
        return

    res = do_register_probe(args.username, args.password, args.device_id, args.proxy, args.scheme, args.clientvar, args.t_epoch)
    print(json.dumps(res, ensure_ascii=False, indent=2))

    # If succeeded, attempt login with plain username and API helper
    if res.get('code') == 0:
        api = PPPokerAPI(proxy=args.proxy)
        data = api.login(username=args.username, password=args.password, device_id=args.device_id)
        print('[LOGIN]', json.dumps(data, ensure_ascii=False))


if __name__ == '__main__':
    main()
