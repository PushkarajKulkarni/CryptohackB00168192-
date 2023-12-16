from math import gcd
# Given values
N = 0x7fe8cafec59886e9318830f33747cafd200588406e7c42741859e15994ab62410438991ab5d9fc94f386219e3c27d6ffc73754f791e7b2c565611f8fe5054dd132b8c4f3eadcf1180cd8f2a3cc756b06996f2d5b67c390adcba9d444697b13d12b2badfc3c7d5459df16a047ca25f4d18570cd6fa727aed46394576cfdb56b41

e = 0x10001

k = 0x372f0e88f6f7189da7c06ed49e87e0664b988ecbee583586dfd1c6af99bf20345ae7442012c6807b3493d8936f5b48e553f614754deb3da6230fa1e16a8d5953a94c886699fc2bf409556264d5dced76a1780a90fd22f3701fdbcb183ddab4046affdc4dc6379090f79f4cd50673b24d0b08458cdbe509d60a4ad88a7b4e2921

c = 0x5233da71cc1dc1c5f21039f51eb51c80657e1af217d563aa25a8104a4e84a42379040ecdfdd5afa191156ccb40b6f188f4ad96c58922428c4c0bc17fd5384456853e139afde40c3f95988879629297f48d0efa6b335716a4c24bfee36f714d34a4e810a9689e93a0af8502528844ae578100b0188a2790518c695c095c9d677b

possible_factors = [k-1, k+1]
for i in range(1, 9):
	factor = pow(k, 1<<i, N) + 1
	possible_factors.append(factor)
  
actual_factors = []

for i in possible_factors:
  f = gcd(i, N)
	print(f) # This will spit out factors
  if f != 1:
    actual_factors.append(f)
assert len(actual_factors) == 2

totient = (actual_factors[0] - 1) * (actual_factors[1] - 1)

# Modular multiplicative inverse
d = pow(e, -1, N) # python 3.8

p = pow(c, d, N) # plaintext

# Print solution
try:
  print(bytes.fromhex(hex(p)[2:]))
except:
  print(bytes.fromhex('0'+hex(p)[2:]))
