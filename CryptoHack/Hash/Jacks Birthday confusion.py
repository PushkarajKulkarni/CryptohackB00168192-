from math import factorial
n = 2048
for i in range(n):
	probability = 1 - factorial(n) / (factorial(n - i)*pow(n,i))
	if probability > 0.75:
		print(i)
		break