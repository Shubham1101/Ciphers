Slayer = [0xb,0xf,0x3,0x2,0xa,0xc,0x9,0x1,
		  0x6,0x7,0x8,0x0,0xe,0x5,0xd,0x4]

Slayerinv = [0xb,0x7,0x3,0x2,0xf,0xd,0x8,0x9,
			 0xa,0x6,0x4,0x0,0x5,0xe,0xc,0x1]

RC = [0x0000000000000000,0x13198a2e03707344,0xa4093822299f31d0,
	  0x082efa98ec4e6c89,0x452821e638d01377,0xbe5466cf34e90c6c,
	  0x7ef84f78fd955cb1,0x85840851f1ac43aa,0xc882d32f25323c54,
	  0x64a51195e0e3610d,0xd3b5a399ca0c2399,0xc0ac29b7c97c50dd]

m0 = [2184,16452,8706,4368,34944,1092,8226,4353,34824,17472,546,4113,32904,17412,8736,273]
m1 = [34944,1092,8226,4353,34824,17472,546,4113,32904,17412,8736,273,2184,16452,8706,4368]

alpha = 0xc0ac29b7c97c50dd

def extendkey(key):
	k0 = key >> 64
	k1 = key & 0xffffffffffffffff
	Key = (((k0 & 1) << 63) + (k0 >> 1)) ^ (k0 >> 63)
	Key = (k0 << 128) + (Key << 64) + k1
	return Key

def sbox(state):
	buffer = state
	state = 0
	for i in range(16):
		state = state + (Slayer[(buffer >> (i*4)) & 0xf] << (i*4))
	return state

def invsbox(state):
	buffer = state
	state = 0
	for i in range(16):
		state = state + (Slayerinv[(buffer >> (i*4)) & 0xf] << (i*4))
	return state

def M0(state):
	ans = 0
	for i in range(16):
		buff = state & m0[i]
		temp = 0
		for j in range(16):
			temp = temp ^ ((buff >> j) & 1)
		ans = (ans << 1) + temp
	return ans

def M1(state):
	ans = 0
	for i in range(16):
		buff = state & m1[i]
		temp = 0
		for j in range(16):
			temp = temp ^ ((buff >> j) & 1)
		ans = (ans << 1) + temp
	return ans

def Mprime(state):
	buffer = state
	state = 0
	state = state + (M0((buffer >> 48) & 0xffff) << 48)
	state = state + (M1((buffer >> 32) & 0xffff) << 32)
	state = state + (M1((buffer >> 16) & 0xffff) << 16)
	state = state + (M0((buffer >>  0) & 0xffff) <<  0)
	return state

def shiftrows(state):
	buffer = state
	state = 0
	state = state + (((buffer >> 60) & 0xf) << 60)
	state = state + (((buffer >> 40) & 0xf) << 56)
	state = state + (((buffer >> 20) & 0xf) << 52)
	state = state + (((buffer >>  0) & 0xf) << 48)
	state = state + (((buffer >> 44) & 0xf) << 44)
	state = state + (((buffer >> 24) & 0xf) << 40)
	state = state + (((buffer >>  4) & 0xf) << 36)
	state = state + (((buffer >> 48) & 0xf) << 32)
	state = state + (((buffer >> 28) & 0xf) << 28)
	state = state + (((buffer >>  8) & 0xf) << 24)
	state = state + (((buffer >> 52) & 0xf) << 20)
	state = state + (((buffer >> 32) & 0xf) << 16)
	state = state + (((buffer >> 12) & 0xf) << 12)
	state = state + (((buffer >> 56) & 0xf) <<  8)
	state = state + (((buffer >> 36) & 0xf) <<  4)
	state = state + (((buffer >> 16) & 0xf) <<  0)
	return state

def invshiftrows(state):
	buffer = state
	state = 0
	state = state + (((buffer >> 60) & 0xf) << 60)
	state = state + (((buffer >>  8) & 0xf) << 56)
	state = state + (((buffer >> 20) & 0xf) << 52)
	state = state + (((buffer >> 32) & 0xf) << 48)
	state = state + (((buffer >> 44) & 0xf) << 44)
	state = state + (((buffer >> 56) & 0xf) << 40)
	state = state + (((buffer >>  4) & 0xf) << 36)
	state = state + (((buffer >> 16) & 0xf) << 32)
	state = state + (((buffer >> 28) & 0xf) << 28)
	state = state + (((buffer >> 40) & 0xf) << 24)
	state = state + (((buffer >> 52) & 0xf) << 20)
	state = state + (((buffer >>  0) & 0xf) << 16)
	state = state + (((buffer >> 12) & 0xf) << 12)
	state = state + (((buffer >> 24) & 0xf) <<  8)
	state = state + (((buffer >> 36) & 0xf) <<  4)
	state = state + (((buffer >> 48) & 0xf) <<  0)
	return state

def PRINCEcore(state,k):
	state = state ^ k
	state = state ^ RC[0]
	for i in (1,2,3,4,5):
		state = sbox(state)
		state = Mprime(state)
		state = shiftrows(state)
		state = state ^ RC[i]
		state = state ^ k
	state = sbox(state)
	state = Mprime(state)
	state = invsbox(state)
	for i in (6,7,8,9,10):
		state = state ^ k
		state = state ^ RC[i]
		state = invshiftrows(state)
		state = Mprime(state)
		state = invsbox(state)
	state = state ^ RC[11]
	state = state ^ k
	return state

def Encrypt(plaintext,key):
	Key = extendkey(key)
	k0 = Key >> 128
	kp = (Key >> 64) & 0xffffffffffffffff
	k1 = Key & 0xffffffffffffffff
	ciphertext = plaintext ^ k0
	ciphertext = PRINCEcore(ciphertext,k1)
	ciphertext = ciphertext ^ kp
	return ciphertext

def Decrypt(ciphertext,key):
	key = key ^ alpha
	Key = extendkey(key)
	k0 = Key >> 128
	kp = (Key >> 64) & 0xffffffffffffffff
	k1 = Key & 0xffffffffffffffff
	plaintext = ciphertext ^ kp
	plaintext = PRINCEcore(plaintext,k1)
	plaintext = plaintext ^ k0
	return plaintext

print("Operations:")
print("Encrypt -> 0")
print("Decrypt -> 1")
print()

operation = int(input("Select operation: "))

if (operation != 0) and (operation != 1):
	print("Invalid Input")

if operation == 0:
	plaintext = int(input("Enter plaintext: "))
	key = int(input("Enter key: "))
	ciphertext = Encrypt(plaintext,key)
	print()
	print("Ciphertext:",ciphertext)

if operation == 1:
	ciphertext = int(input("Enter ciphertext: "))
	key = int(input("Enter key: "))
	plaintext = Decrypt(ciphertext,key)
	print()
	print("Plaintext:",plaintext)