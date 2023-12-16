from array import array 
from Crypto.Util.number import bytes_to_long, long_to_bytes

# From Crypto SE 
input1 = array('I',  [0x6165300e,0x87a79a55,0xf7c60bd0,0x34febd0b,0x6503cf04,
    0x854f709e,0xfb0fc034,0x874c9c65,0x2f94cc40,0x15a12deb,0x5c15f4a3,0x490786bb,
    0x6d658673,0xa4341f7d,0x8fd75920,0xefd18d5a])

input2 = array('I', [x^y for x,y in zip(input1, [0, 0, 0, 0, 0, 1<<10, 0, 0, 0, 0, 1<<31, 0, 0, 0, 0, 0])])

input1 = bytes(input1)
input2 = bytes(input2)
assert md5(input1).hexdigest() == md5(input2).hexdigest()

print(bytes_to_long(input1))
print(bytes_to_long(input2))