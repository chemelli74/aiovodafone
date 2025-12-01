from sjcl import SJCL

derived_key = "7f5488220c3e10216dcd0da5cc73fa23"
plain_data = "pippo"

data = SJCL().encrypt(
    plain_data.encode("utf-8"), derived_key, mode="ccm", count=1000, dkLen=16
)

for k, v in data.items():
    if isinstance(v, bytes):
        data[k] = v.decode("utf-8")
encrypted_data = data
print("2. encrypted data: ", encrypted_data)
