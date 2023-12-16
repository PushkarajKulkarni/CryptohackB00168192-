from Crypto.Util.number import bytes_to_long
from pwn import * 
import json 
from Crypto.Cipher import AES
from os import urandom

class LCG:
    def __init__(self, a, b, m, seed):
        self.a = a
        self.b = b
        self.m = m
        self.state = seed
        self.counter = 0

    def refresh(self):
        self.counter = 0
        self.state = bytes_to_long(urandom(6))

    def next_state(self):
        self.state = (self.a * self.state + self.b) % self.m

    def get_random_bits(self, k):
        if self.counter == 16:
            self.refresh()
        self.counter += 1
        self.next_state()
        return self.state >> (48 - k)

    def get_random_bytes(self, number):
        bytes_sequence = b''
        for i in range(number):
            bytes_sequence += bytes([self.get_random_bits(8)])
        return bytes_sequence

a = 0x1337deadbeef
b = 0xb
m = 2**48

io = remote('socket.cryptohack.org', int(13396))
io.recvline()

def attack(y, k, s, m, a, c):
    """
    Recovers the states associated with the outputs from a truncated linear congruential generator.
    More information: Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"
    :param y: the sequential output values obtained from the truncated LCG (the states truncated to s most significant bits)
    :param k: the bit length of the states
    :param s: the bit length of the outputs
    :param m: the modulus of the LCG
    :param a: the multiplier of the LCG
    :param c: the increment of the LCG
    :return: a list containing the states associated with the provided outputs
    """
    diff_bit_length = k - s

    # Preparing for the lattice reduction.
    delta = c % m
    y = vector(ZZ, y)
    for i in range(len(y)):
        # Shift output value to the MSBs and remove the increment.
        y[i] = (y[i] << diff_bit_length) - delta
        delta = (a * delta + c) % m

    # This lattice only works for increment = 0.
    B = matrix(ZZ, len(y), len(y))
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** i
        B[i, i] = -1

    B = B.LLL()

    # Finding the target value to solve the equation for the states.
    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]

    # Recovering the states
    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        # Adding the MSBs and the increment back again.
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m

    return x

to_send = {'option': 'get_a_challenge'}
io.sendline(json.dumps(to_send).encode())
response = json.loads(io.recvline().decode())

plaintext = bytes.fromhex(response['plaintext'])
iv = bytes.fromhex(response['IV'])

# Collect the PRNG output related to the generation of the key
rng_plaintext = [i for i in plaintext[8:]]
rng_iv = [i for i in iv[:8]]
key = b''

# Recover the first 8 states of the PRNG, when generate the plaintext
rng_plaintext_states = attack(rng_plaintext, 48, 8, m, a, b)
lcg = LCG(a, b, m, rng_plaintext_states[-1])

# The first 8 bytes of the key will be the last 8 states of the PRNG used for
# generating the plaintext, where the plaintext has the first 8 states
for i in range(8):
    key += bytes([lcg.get_random_bits(8)])

# Recover the last 8 states of the PRNG, when generate the IV
# The first 8 bytes of the key will be the first 8 states of the PRNG used for
# generating the IV, where the IV is the following 8 states
rng_iv_states = attack(rng_iv, 48, 8, m, a, b)
state = rng_iv_states[0]
temp = b''
# Generating the output from the previous states, which can be recovered from the known state s
# Denote the previous state as x, then ax + b = s, thus x = (s - b) * a ^ -1
for i in range(8):
    prev_state = ((state - b) * pow(a, -1, m)) % m 
    temp += bytes([prev_state >> 40])
    state = prev_state

# Append the key to the temp value generated
key = key + temp[::-1]

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)

to_send = {'option': 'validate', 'ciphertext': ciphertext.hex()}
io.sendline(json.dumps(to_send).encode())
response = json.loads(io.recvline().decode())
print(response['msg'])