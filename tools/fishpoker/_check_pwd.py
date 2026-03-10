import hashlib

pwd = "jpprfhnvm8920"
target = "b12be760876825fb45fee46717534a75"

md5_1 = hashlib.md5(pwd.encode("utf-8")).hexdigest().lower()
md5_2 = hashlib.md5(md5_1.encode("utf-8")).hexdigest().lower()
md5_upper = hashlib.md5(pwd.encode("utf-8")).hexdigest().upper()
md5_of_upper = hashlib.md5(md5_upper.encode("utf-8")).hexdigest().lower()
md5_bytes = hashlib.md5(pwd.encode("utf-8")).digest()
md5_of_raw = hashlib.md5(md5_bytes).hexdigest().lower()

print(f"password:          {pwd}")
print(f"target:            {target}")
print()
print(f"md5(pwd):          {md5_1}  {'MATCH!' if md5_1==target else ''}")
print(f"md5(md5(pwd)):     {md5_2}  {'MATCH!' if md5_2==target else ''}")
print(f"md5(MD5.upper):    {md5_of_upper}  {'MATCH!' if md5_of_upper==target else ''}")
print(f"md5(md5_raw):      {md5_of_raw}  {'MATCH!' if md5_of_raw==target else ''}")

# Salted variants
for salt in ["fishpoker", "FishPoker", "pppoker", "PPPoker", "globle",
             "1831BFE11318", "2E-E9-ED-23-7F-5B", "tequ31"]:
    h1 = hashlib.md5((pwd + salt).encode("utf-8")).hexdigest().lower()
    h2 = hashlib.md5((salt + pwd).encode("utf-8")).hexdigest().lower()
    h3 = hashlib.md5((md5_1 + salt).encode("utf-8")).hexdigest().lower()
    h4 = hashlib.md5((salt + md5_1).encode("utf-8")).hexdigest().lower()
    for label, h in [
        (f"md5(pwd+'{salt}')", h1),
        (f"md5('{salt}'+pwd)", h2),
        (f"md5(hash+'{salt}')", h3),
        (f"md5('{salt}'+hash)", h4),
    ]:
        if h == target:
            print(f"{label}: {h}  MATCH!")

# UTF-16
for enc in ["utf-16-le", "utf-16-be", "utf-16", "latin-1", "ascii"]:
    try:
        h = hashlib.md5(pwd.encode(enc)).hexdigest().lower()
        if h == target:
            print(f"md5(pwd.encode('{enc}')): {h}  MATCH!")
    except:
        pass

# SHA1 / SHA256 truncated
sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().lower()
sha256 = hashlib.sha256(pwd.encode("utf-8")).hexdigest().lower()
print(f"\nsha1(pwd):         {sha1}")
print(f"sha256(pwd)[:32]:  {sha256[:32]}")

# XXTEA test - try to find if it's xxtea(md5, key)
try:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from pppoker.protocol import xxtea_encrypt, xxtea_decrypt
    # Try to decrypt target as if it were xxtea-encrypted md5
    target_bytes = bytes.fromhex(target)
    for key_str in ["fishpoker", "FishPoker", "pppoker", "globle", md5_1[:16], pwd]:
        key_bytes = key_str.encode("utf-8")[:16].ljust(16, b"\x00")
        try:
            dec = xxtea_decrypt(target_bytes, key_bytes)
            print(f"xxtea_decrypt(target, '{key_str}'): {dec.hex()}")
        except:
            pass
    # Try to encrypt md5 and see if it matches
    md5_raw = bytes.fromhex(md5_1)
    for key_str in ["fishpoker", "FishPoker", "pppoker", "globle"]:
        key_bytes = key_str.encode("utf-8")[:16].ljust(16, b"\x00")
        try:
            enc = xxtea_encrypt(md5_raw, key_bytes)
            print(f"xxtea_encrypt(md5, '{key_str}'): {enc.hex()}  {'MATCH!' if enc.hex()==target else ''}")
        except:
            pass
except ImportError as e:
    print(f"\nXXTEA not available: {e}")

print("\nDone.")
