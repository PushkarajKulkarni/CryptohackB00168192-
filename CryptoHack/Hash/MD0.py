from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *
from json import loads, dumps
import os  

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

r = remote("socket.cryptohack.org", 13388)
payload = b'a'*15
payload_json = dumps({"option" : "sign", "message" : payload.hex()}).encode()
r.sendlineafter(b"You'll never forge my signatures!\n", payload_json)
data = r.recvline()
sign = loads(data.decode())["signature"]
print(sign)


new_payload = b'admin=True'
payload = pad(payload,16) + new_payload
sign = bytes.fromhex(sign)

new_sign = bxor(AES.new(pad(new_payload,16), AES.MODE_ECB).encrypt(sign), sign)
payload_json = dumps({"option" : "get_flag", "message" : payload.hex(), "signature" : new_sign.hex()})
r.sendline(payload_json.encode())
r.interactive()