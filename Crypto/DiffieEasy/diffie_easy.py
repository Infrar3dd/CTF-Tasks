q = 1357
g = 10
aa = 0
bb = 0
for a in range(1000):
	if((g**a)%q == 419):
		print(a)
		aa = a
		break
for b in range(1000):
	if((g**b)%q == 34):
		print(b)
		bb = b
		break

if((g**(aa*bb)%q) == 33):
	print("yes")