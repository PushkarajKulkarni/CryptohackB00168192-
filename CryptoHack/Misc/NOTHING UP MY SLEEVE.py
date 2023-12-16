from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto.Random import random
from tqdm import tqdm 
from pwn import * 
import json 

io = remote('socket.cryptohack.org', 13387)
print(io.recvline())

class RNG:
    def __init__(self, seed, P, Q):
        self.seed = seed
        self.P = P
        self.Q = Q

    def next(self):
        t = self.seed
        s = (t * self.P).x
        self.seed = s
        r = (s * self.Q).x
        return r & (2**(8 * 30) - 1)

# The point Q sent follows P = Q, for an easier time
send_x = "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
send_y = "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
to_send = {'x': send_x, 'y': send_y}
io.sendline(json.dumps(to_send).encode())
print(io.recvline())

# Recover the rng outputs from the spins observed
def recover_rng_output(spins):
    state = 0 
    for spin in spins:
        state *= 37
        state += spin
    return state 

# Reconstruct the output from the PRNG, the 240 least significant bits of 
# the RNG used for generating the spins
def reconstruct_rng_outputs():
    shuffle_states = []
    current_shuffle = []
    
    for _ in range(47 * 2):
        # Random choice should be enough for observing the values
        # if failed then restart the script
        pick = random.choice(['ODD', 'EVEN'])
        to_send = {'choice': pick}

        io.sendline(json.dumps(to_send).encode())
        response = json.loads(io.recvline().decode())
        msg = response['msg']
        spin = response['spin']
        current_shuffle.append(spin)
        
        # New set of spins 
        if 'Good evening' in msg:
            shuffle_states.append(current_shuffle)
            current_shuffle = []
        
        # Two states is needed for the recovery
        if len(shuffle_states) == 2:
            break 
    
    return shuffle_states

# Recover the full state of the RNG 
def recover_rng_state():
    outputs = reconstruct_rng_outputs()
    outputs = list(map(lambda x: recover_rng_output(x), outputs))

    # Brute force the MSB 16 bits of the first state observed
    for i in tqdm(range(2 ** 16)):
        # Possible state 
        possible = i * 2 ** 240 + outputs[0]
        send = Point(int(send_x, 16), int(send_y, 16))

        result = send * possible 
        # Comparing the next state generated to the next state output observed 
        if result.x & (2**(8 * 30) - 1) == outputs[1]:
            return possible

# Generate the spins
def rebase(n, b=37):
    if n < b:
        return [n]
    else:
        return [n % b] + rebase(n // b, b)

# The state used for the next batch of spins
state = recover_rng_state()
G = Point(int(send_x, 16), int(send_y, 16))
rng = RNG(state, G, G)

# Generate the next state used for the spins
next_state = rng.next()
spins = rebase(next_state & (2**(8 * 30) - 1))

# There are less than 50 spins left allowed, but too lazy to get
# the correct number of spins left
for _ in range(50):
    # Get the current spin, we go for the juicy 35 point guess
    current_spin = spins.pop()
    to_send = {'choice': current_spin}

    io.sendline(json.dumps(to_send).encode())
    response = json.loads(io.recvline().decode())
    msg = response['msg']

    # If flag is returned 
    if "flag" in msg: 
        print(msg)
        break 
    
    # If there is no spin left in the spins cycle
    if len(spins) == 0:
        next_state = rng.next()
        spins = rebase(next_state & (2**(8 * 30) - 1))