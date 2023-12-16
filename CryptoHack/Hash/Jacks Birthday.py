n = 1 << 11
P = 1
for i in range(1, n):
    P = pow((1 - 1/n), i)
    nP = 1 - P
    if nP > 0.5:
        print(i)
        break
