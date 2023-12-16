from pwn import * 
import json 
import base64 

io = remote('socket.cryptohack.org', 13370)
io.recvline()

FLAG = "crypto{????????????}"
guesses = []

# Possible characters at all unknown positions of the flag
for _ in range(len(FLAG) - 8):
    chars = [i for i in range(33, 127)]
    guesses.append(chars)

# Check whether each position has only 1 possibility
def check_guess(guesses):
    for chars in guesses:
        if len(chars) != 1:
            return False 
    
    return True 

# Remove chars from the guesses array, as the ciphertext bytes cannot be
# in the flag bytes
def remove_chars(ciphertext, guesses):
    unknown = ciphertext[7:len(FLAG) - 1]

    for i in range(len(unknown)):
        try:
            guesses[i].remove(unknown[i])
        except Exception:
            pass 

# Print out the length of each position guess space 
# for ease of tracking what's going on
def status(guesses):
    temp = []

    for i in range(len(FLAG) - 8):
        temp.append(len(guesses[i]))
    
    print(temp)

to_send = {'msg': 'request'}

while not check_guess(guesses):
    io.sendline(json.dumps(to_send).encode())

    response = io.recvline().decode()

    # Discard error messages
    if "error" not in response:
        ciphertext = json.loads(response)['ciphertext']
        ciphertext = base64.b64decode(ciphertext)
        remove_chars(ciphertext, guesses)
        status(guesses)

print(guesses)
# guesses = [[117], [110], [114], [52], [110], [100], [48], [109], [95], [48], [55], [112]]
flag = b''
for i in range(len(FLAG) - 8):
    flag += bytes([guesses[i][0]])

print(b'crypto{' + flag + b'}')