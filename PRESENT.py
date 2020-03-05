sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
player = [0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
		4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
		8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
		12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]
roundkeys = []

def generateRoundKeys(key):
	for i in range(1,33):
		roundkeys.append(key>>16)
		key = ((key & (2**19-1)) << 61) + (key>>19)
		key = (sbox[key>>76] << 76) + (key & (2**76-1))
		key = (key ^ (i << 15))

def addRoundKey(state,roundkey):
	return (state ^ roundkey)

def sBoxLayer(state):
	output = 0
	for i in range(16):
		output += (sbox[(state >> (i*4)) & 0xf] << (i*4))
	return output

def pLayer(state):
	output = 0
	for i in range(64):
		output += (((state >> i) & 0x1) << player[i])
	return output

plaintext = int(input("Enter Plaintext: "))
key = int(input("Enter Key: "))
state = plaintext
ciphertext = -1

generateRoundKeys(key)
for i in range(31):
	state = addRoundKey(state,roundkeys[i])
	state = sBoxLayer(state)
	state = pLayer(state)

ciphertext = addRoundKey(state,roundkeys[31])

print()
print("Ciphertext:",ciphertext)