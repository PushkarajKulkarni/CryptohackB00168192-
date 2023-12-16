from pwn import *
import json
block1 = b'a'*32
block2 = b'b'*32

m1 = (block1 + block2).hex()
m2 = (block2 + block1).hex()
payload = json.dumps({"m1" : m1, "m2" : m2}).encode()
r = remote("socket.cryptohack.org", 13405)
r.sendlineafter(b'in JSON: ', payload)
data = r.recvline()
print(data)
r.close()