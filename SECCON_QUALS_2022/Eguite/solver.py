from z3 import *

r1 = BitVec('r1', 48)
r2 = BitVec('r2', 48)
r3 = BitVec('r3', 48)
r4 = BitVec('r4', 48)

s = Solver()
s.add(r1 + r2 == 0x8b228bf35f6a)
s.add(r3 + r2 == 0xe78241)
s.add(r4 + r3 == 0xfa4c1a9f)
s.add(r1 + r4 == 0x8b238557f7c8)
s.add(r3 ^ r2 ^ r4 == 0xf9686f4d)
print(s.check())
m = s.model()
print(m)

# r1 = 8B228B98E458
# r2 = 5A7B12
# r3 = 8D072F
# r4 = F9BF1370

# SECCON{8B228B98E458-5A7B12-8D072F-F9BF1370}