from pwn import * 
import json 

io = remote('socket.cryptohack.org', 13372)
io.recvline()

FLAG = b'crypto{????????????????????}'
to_send = {'option': 'encrypt_data', 'input_data': FLAG.hex()}
io.sendline(json.dumps(to_send).encode())
enc_data = json.loads(io.recvline().decode())['encrypted_data']
enc_data = bytes.fromhex(enc_data)
key = xor(enc_data, FLAG)

# Request the flag immediately after, then decrypt using the key obtained
to_send = {'option': 'get_flag'}
io.sendline(json.dumps(to_send).encode())
enc_flag = json.loads(io.recvline().decode())['encrypted_flag']
enc_flag = bytes.fromhex(enc_flag)
print(xor(enc_flag, key))