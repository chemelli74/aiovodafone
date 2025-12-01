import binascii
import hashlib
import json
from base64 import b64decode

from Cryptodome.Cipher import AES
from sjcl import SJCL


def derive_key_hex(
    password: str, salt_hex: str, iterations: int = 1000, dklen: int = 16
) -> str:
    """Deriva la chiave PBKDF2-HMAC-SHA256 e ritorna la chiave in esadecimale (minuscole).
    - password: stringa della password
    - salt_hex: salt come stringa esadecimale (es. "a1b2c3...")
    - iterations: numero di iterazioni PBKDF2 (default 1000)
    - dklen: lunghezza in byte della chiave derivata (default 16 = 128 bit)
    """
    salt = bytes.fromhex(salt_hex)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen
    )
    return binascii.hexlify(key).decode("utf-8")


def sjcl_json_decrypt(password_or_key, json_data, extra_params=None, out_params=None):
    """Python equivalent of SJCL's e.decrypt(a, b, c, d)
    - password_or_key: either a string (password) or bytes (key)
    - json_data: SJCL JSON object or string
    - extra_params: dict, merged with the JSON settings
    - out_params: dict, will be updated with encryption params (key, salt, etc)
    """
    # --- Step 1: normalize input ---
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = dict(json_data)

    extra_params = extra_params or {}
    out_params = out_params or {}

    # Merge with SJCL defaults (approximated)
    defaults = {
        "iter": 1000,
        "ks": 128,
        "ts": 64,
        "mode": "ccm",
        "cipher": "aes",
    }

    # Merge order like SJCL: defaults <- data <- extra_params
    b = {**defaults, **data, **extra_params}

    # --- Step 2: decode salt & iv ---
    if isinstance(b.get("salt"), str):
        b["salt"] = b64decode(b["salt"])
    if isinstance(b.get("iv"), str):
        b["iv"] = b64decode(b["iv"])

    # --- Step 3: validate parameters ---
    if not (b["mode"] in ("ccm", "gcm") and b["cipher"] == "aes"):
        raise ValueError(
            "Unsupported mode/cipher: {}/{}".format(b["mode"], b["cipher"])
        )
    if len(b["iv"]) < 2 or len(b["iv"]) > 16:
        raise ValueError("Invalid IV length for AES-CCM")

    # --- Step 4: derive key if password is string ---
    if isinstance(password_or_key, str):
        # PBKDF2-HMAC-SHA256 like SJCL.misc.cachedPbkdf2
        dklen = b["ks"] // 8
        key = hashlib.pbkdf2_hmac(
            "sha256", password_or_key.encode("utf-8"), b["salt"], b["iter"], dklen
        )
    else:
        key = password_or_key

    # --- Step 5: prepare ciphertext and tag ---
    ct_and_tag = b64decode(b["ct"])
    tag_len = b["ts"] // 8
    ciphertext = ct_and_tag[:-tag_len]
    tag = ct_and_tag[-tag_len:]

    # --- Step 6: optional AAD ---
    adata = b.get("adata", "")
    if isinstance(adata, str):
        adata = adata.encode("utf-8")
    elif adata is None:
        adata = b""

    # --- Step 7: decrypt ---
    try:
        if b["mode"] == "ccm":
            cipher = AES.new(key, AES.MODE_CCM, nonce=b["iv"], mac_len=tag_len)
            if adata:
                cipher.update(adata)
            plaintext = cipher.decrypt(ciphertext)
            cipher.verify(tag)
        else:  # GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce=b["iv"])
            if adata:
                cipher.update(adata)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

    # --- Step 8: fill output info like SJCL ---
    out_params.update(b)
    out_params["key"] = key

    return plaintext.decode("utf-8", errors="replace")


# Example usage:
if __name__ == "__main__":
    # Example SJCL JSON payload
    sjcl_json = {
        "iv": "axY/8UgKXQw=",
        "v": 1,
        "iter": 1000,
        "ks": 128,
        "ts": 64,
        "mode": "ccm",
        "adata": "",
        "cipher": "aes",
        "salt": "fjEmrVTeYgA=",
        "ct": "g+m9SdWSiH+3t06zNHhh5WoG/ZTvi/276a66hK0teIJroYXqQJGDcxwr1TYcGiv9r54xTv1hC9S05M1s8RA5f1cnewEI1UBdRHNbWKfUOW3GnWY16DfUOJNu1RmqpBtSCRfVxkRqzp1jH9zqlk4Epi0XYy1YisjIQhE+8F5NDKvT6QdHiF4DkvXKvboQXNiazeJ1H/I2WQtMIP3oMrWd6nJvWYq8X5UafDhArmyoR+4NPfjx3pWxt1tCGQ4lmz9y8QPZVnHD1t7K/q12IQB3CxPHF4RkxSYhRtsasAQo1XL4cHfIp953OvDoxI0dAdhBrk2mf3gLuiMT482oyjv00lHa507KQ9on1YnZWJT9ld5JWsAeo+4iaVrXYor/OqUCJWOiUsSkh+uvAi6AzB1iO50FCdcGMHa0BXRrwuamf21q1CCuM2wQo7he7xEY29BnhinlHZ4Zqal5UFpR/EAR9PWvcx/Lv3ULRcZzmJRxUyWbiiNSMgBARa+5224+FyMLMh4doHZoiP2kLv2kUd2Iu99Nomykouw49y8cILv0bDVGLIRMDlo80whE8qCwNVxUabINOfBfyB5TbZF5m1RzPuW6XvGXRd/cZCpCyoOLAptml8LEVzTUbiKb+Fo27psBMF8zGtDwUA4Lzw8v/VTHdDndx0d2X0WloyQ5ch6w2I3ezkZMhKhQ2WLHEPVM4ffioqw+e58tBkj8BUsbh4EzrEUehXu7CWqBZDXP9OAY4wUP3NIm0rp593I30eoxdhLlFiWjEkjWx0eJzuvbQ5m9Ep+ELyIceWS9CHwJCGqCP0fgid0zxTm2rle7CFMnod9genbs6v6SkKJ3JND0yyYVeXRyXUEQrkM6/+YhzNaCNu7nx9fREOOrNsG2azVFlu+n/XF0IGJN7ow7O1mukpJhbDSEi3bCloaNlBA2EcbWKKqstnrX6Skep3L1Dknt0Mml7TkwJjoRr7cnayLLGrE+P07B9WD2eY/f0Oc2e/JoQJJChnEbddxFWn3CPHuKxFQyg7biw4EfXuBh5snfOXsc5+CYFk7PiTlLo/0FGyNM64ibPM1H13aeZ27nz3caT+HoyG6XbsR1IFqqPjyh17QsoRcmsLfT/F05889l5jaUfp5NxM3YadNhUFAm+jWnFEwGgeMb7JhnXANcKnd7vMgptAKE71vayX3i4OOos3JMucqtzZ6ZU8asUxtoesL+xF1WYJuwVynwFHNl9UEf7yiuwqalgSCQ3onAEWdInxrdH6IP+fOBA7fy+xt7SVti/tTCPOHoa+enlIe2bKovEssRljSA8+fB0hXBZRtBnIXc3IcCQYdFQkm3rAnmHNDam0lk+265ilLA8LVxa36nuR/yk7JjLk+NawLOP65fpdAzDoIiympvcmTuRNov3PZqOV6M1DQd6UmBKt3uxOgctWxNIFl+7HR71krNtHwjQyiNGQkSEYZ8V6XvGfFlENyGKk/8pOVGGbn6qCaiMbjdfyiSRXyGj8/dAFTJM2hukVyMxsMaFghkMCpQ7IcSPA1RCCR6bBQJGPcZOFIvMzqpmhJDbeuj5UmOlghm0UAwoNYn3g==",
    }

    password = "D8QLRCEGG4L2"
    salt = "4F2F18495E52D2C3"  # if you override the salt manually

    ks_bits = 128
    dklen_bytes = ks_bits // 8  # es. 128 bits -> 16 bytes

    # deriviamo la chiave correttamente da salt (base64!)
    dk_hex = derive_key_hex(password, salt, iterations=1000, dklen=dklen_bytes)

    print("1. set dk: " + dk_hex + " salt: " + salt)

    try:
        plaintext = SJCL().decrypt(sjcl_json, dk_hex)
        print("✅ Plaintext:", plaintext)
    except Exception as e:
        print("❌ Error:", e)
