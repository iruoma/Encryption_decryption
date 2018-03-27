# Encryption_decryption
RC4 Encrypting and Decrypting using Python 
The RC4 algorithm is the most used software-based stream ciphers in the world. 
RC4 creates a pseudorandom stream of bits that is also referred to as a keystream. 
The RC4 cipher consists of two (2) parts which are the KSA (Key Scheduling Algorithm) and the PRGA (Pseudo-Random Generation Algorithm)
PRGA (pseudo-random generation algorithm) is the lookup stage of the RC4 cipher. The output byte is chosen by making a lookup of the values of S(i) and S(J) in the array. 
It will then add them together mod 256 and use the sum as the subsequent index into S. 
Then, S(S(i)+S(j)) will be used as a byte of the resulting keystream (K)
