import sys
from typing import Tuple

POLYNOMIAL = 0x104C11DB7

def Calculate(crc: int, length: int, newCrc: int, offset: int, existingOffsetValue: int) -> int:
    newCrc = reverse32(newCrc)
    crc = reverse32(crc)
    delta = crc ^ newCrc
    delta = multiplyMod(
        reciprocalMod(
            powMod(2, (length - offset) * 8)
        ),
        delta & 0xFFFFFFFF
    )
    result = existingOffsetValue ^ reverse32(delta)
    return result

def reverse32(x: int) -> int:
	y: int = 0
	for _ in range(32):
		y = (y << 1) | (x & 1)
		x >>= 1
	return y

def multiplyMod(x: int, y: int) -> int:
	# Russian peasant multiplication algorithm
	z: int = 0
	while y != 0:
		z ^= x * (y & 1)
		y >>= 1
		x <<= 1
		if (x >> 32) & 1 != 0:
			x ^= POLYNOMIAL
	return z

def powMod(x: int, y: int) -> int:
	# Exponentiation by squaring
	z: int = 1
	while y != 0:
		if y & 1 != 0:
			z = multiplyMod(z, x)
		x = multiplyMod(x, x)
		y >>= 1
	return z

def divideAndRemainder(x: int, y: int) -> Tuple[int,int]:
	if y == 0:
		raise ValueError("Division by zero")
	if x == 0:
		return (0, 0)
	
	ydeg: int = getDegree(y)
	z: int = 0
	for i in range(getDegree(x) - ydeg, -1, -1):
		if (x >> (i + ydeg)) & 1 != 0:
			x ^= y << i
			z |= 1 << i
	return (z, x)

def reciprocalMod(x: int) -> int:
	# Based on a simplification of the extended Euclidean algorithm
	y: int = x
	x = POLYNOMIAL
	a: int = 0
	b: int = 1
	while y != 0:
		q, r = divideAndRemainder(x, y)
		c = a ^ multiplyMod(q, b)
		x = y
		y = r
		a = b
		b = c
	if x == 1:
		return a
	else:
		raise ValueError("Reciprocal does not exist")

def getDegree(x: int) -> int:
	return x.bit_length() - 1