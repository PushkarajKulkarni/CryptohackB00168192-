import hashlib

p = 77793805322526801978326005188088213205424384389488111175220421173086192558047
FLAG = b"crypto{???????????????????????}"

# Denote secret (the flag) as s
# The polynomial will be c2 * x ^ 2 + c1 * x + s = y
# From the challenge code, x = c1, and c2 = sha256(c1) 
c1, y = (105622578433921694608307153620094961853014843078655463551374559727541051964080, 25953768581962402292961757951905849014581503184926092726593265745485300657424)
c2 = hashlib.sha256(int.to_bytes(c1, 32, 'big')).digest()
c2 = int.from_bytes(c2, 'big')

# Calculate c2 * c1 ^ 2 + c1 * c1
pol = (c2 * pow(c1, 2, p) + c1 * c1) % p

# s = y - pol
print(int.to_bytes((y - pol) % p, len(FLAG), 'big'))