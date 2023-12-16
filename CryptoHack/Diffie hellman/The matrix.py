import random

P = 2
N = 50
E = 31337

FLAG = b'crypto{??????????????????????????}'

def bytes_to_binary(s):
    bin_str = ''.join(format(b, '08b') for b in s)
    print(bin_str)
    bits = [int(c) for c in bin_str]
    return bits

def generate_mat():
    while True:
        msg = bytes_to_binary(FLAG)
        msg += [random.randint(0, 1) for _ in range(N*N - len(msg))]
        rows = [msg[i::N] for i in range(N)]
        mat = Matrix(GF(2), rows)
        if mat.determinant() != 0 and mat.multiplicative_order() > 10^12:
            return mat

def recover_plaintext(mat):
    temp = ""
    for i in range(N):
        for j in range(N):
            temp = temp + str(mat[j][i])

    temp = temp[:len(FLAG) * 8]
    return int(temp, 2).to_bytes((len(temp) + 7) // 8, 'big')

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

def save_matrix(M, fname):
    open(fname, 'w').write('\n'.join(''.join(str(x) for x in row) for row in M))

ciphertext = load_matrix("flag.enc")
d = pow(E, -1, ciphertext.multiplicative_order())
mat = ciphertext ^ d
print(recover_plaintext(mat))