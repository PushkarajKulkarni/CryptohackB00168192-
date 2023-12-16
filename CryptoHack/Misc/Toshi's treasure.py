from pwn import * 
import json 

io = remote('socket.cryptohack.org', 13384)

hyper_share = json.loads(io.recvline().decode())['y']
for i in range(4):
    io.recvline()

# Send 0 so it is easier to work with, any number for y works
to_send = {'sender': 'hyper', 'msg': 'lmao', 'x': 6, 'y': hex(0)}
io.sendline(json.dumps(to_send).encode())

# The private key returned when the wallet address is invalid
priv_key_fail = json.loads(io.recvline().decode())['privkey']
priv_key_fail = int(priv_key_fail, 16)

# Prime in use, 13th Mersenne prime
prime = 2 ** 521 - 1

# x coordinates of hyper's friends
friends_x = [2, 3, 4, 5]
hyper_x = 6

# The 1k wallet address
hyper_1k_wallet = int("8b09cfc4696b91a1cc43372ac66ca36556a41499b495f28cc7ab193e32eadd30", 16)

# Calculate the x value related to our y value submitted, 
# the product of the fraction used in Lagrange's polynomial
# See https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing#Computationally_efficient_approach
# Or in other words, the product of all x_m / x_m - x_j
x_value = 1

for x in friends_x:
    fraction = x * pow((x - hyper_x), -1, prime)
    x_value = (x_value * fraction) % prime 

# We have priv_key_fail + y * x_value = hyper_1k_wallet
# therefore y = (hyper_1k_wallet - priv_key_fail) / x_value
y = (hyper_1k_wallet - priv_key_fail) % prime 
y = (y * pow(x_value, -1, prime)) % prime 

to_send = {'sender': 'hyper', 'msg': 'lmao', 'x': 6, 'y': hex(y)}
io.sendline(json.dumps(to_send).encode())

# Real private key
real_priv_key = (priv_key_fail + int(hyper_share, 16) * x_value) % prime 
to_send = {'privkey': hex(real_priv_key)}
io.sendline(json.dumps(to_send).encode())
io.interactive()