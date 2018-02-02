import copy

# function to get the length and offset value from the message
def length(m, offset):
    key = convert_hashkey(m)
    length = sum(key)
    a = length % 256
    if a == 0:
        return offset
    else:
        return a

# ksa function with a variable keylength
def KSA(S, keys):
    j = 0
    key = convert_hashkey(keys)
    keylength = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S

# ksa function with char keys
def KSAm(S, keys, keylength):
    j = 0
    for i in range(256):
        j = (j + S[i] + keys[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S

# PRGA function with output
def PRGA(S, len):
    i = 0
    j = 0
    K = []
    for a in range(len):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap

        b = S[(S[i] + S[j]) % 256]
        K.append(b)
    return K

# PRGA function without output
def PRGASTAR(S, length):
    j = 0
    for i in range(length):
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S


# PRGA function without output for encryption
def PRGAe(S, length):
    i = 0
    j = 0
    for a in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap

        K = S[(S[i] + S[j]) % 256]
        yield K

def iprga(i, j, S, len):
        x = 0  # x is a counter
        # looping based on a random number of output bytes
        while x < len:
            # printing the solution of the iprga algorithm
            print('i =', i, ', j =', j, end='')

            # IPRGA algorithm
            K = S[(S[i] + S[j]) % 256]  # getting the keystream
            S[i], S[j] = S[j], S[i]  # swap
            j = (j - S[i] + 256) % 256
            i = (i - 1) % 256

            print(',  Keystream = ', K)

            x += 1

# function to find the xor of two binary values
def xorfunction(a, b):
    m = []
    for c, d in zip(a, b):
        e = c ^ d
        m.append(e)
    return m


# function to convert string to character
def convert_hashkey(s):
    x = [ord(c) for c in s]
    return(x)

# function to split message into 252-bytes and pad
def splitmessage(msg):
    bytes = 252
    packets = [msg[i:i+bytes] for i in range(0, len(msg), bytes)]
    result = []
    plaintextdiv = []
    for i in range(len(packets)):
        sc = "{0:0>4}".format(i)  # creating 4bytes sequence number
        if len(packets[i]) < bytes:
            diff = bytes - int(len(packets[i]))
            b = packets[i] + '1' + ("0" * int(diff - 1))  # padding
            values = str(sc) + str(b)  # concatenating message and sequence number
            plaintextdiv.append(str(b))
            result.append(values)
        else:
            values = str(sc) + str(packets[i])
            plaintextdiv.append(str(packets[i]))
            result.append(values)
    return (plaintextdiv, result, diff) # returns 252bytes, 256bytes (with sequnce number) packets and length of padding )


# function to split 256 bytes messages into 64 bytes
def split2(msg):
    byte = 64
    result = []
    for y in msg:
        packets = [y[i:i + byte] for i in range(0, len(y), byte)]
        result.append(packets)
    m = "10000000000000000000000000000000000000000000000000000000000000256"  # extra packet
    for i in result:
        i.append(m)
    return result

# hash function to get the hash value
def hash(m, offset):
    state = list(range(256))
    hasharray = []
    for i in range(len(m)):
        binlist = []

        # first round of KSA and 2 PRGA'S for M1
        a = KSA(state, m[i][0])
        z = PRGASTAR(a, offset)
        y = length(m[i][0], offset)
        c = PRGASTAR(z, y)

        # KSA and PRGA for M2 - Mn
        for j in range(1, len(m[i])):
            x = KSA(c, m[i][j])
            d = PRGASTAR(x, length(m[i][j], offset))  # result

        last = copy.deepcopy(d)  # deep copy your lists to prevent it from changing
        f = copy.deepcopy(d)

        # do KSA and PRGA with the output being the key for KSA
        v = KSAm(state, f, 256)
        p = PRGA(v, 512)  # loop PRGA 512 times

        # taking the last half of your result
        half = p[256:]
        hal = half

        # binary xor with last half of the second result and the initial result
        xorarray = xorfunction(last, hal)

        # taking the odd values
        odd = xorarray[0::2]
        deepodd = copy.deepcopy(odd)

        # converting to binary
        for i in deepodd:
            tobinary = "{0:08b}".format(i)
            binlist.append(tobinary)

        # picking the last bit from every odd value
        hashbin = ""
        for str in binlist:
            hashbin = hashbin + str[-1:]  # hash value in binary

        # converting the hash value from binary to ascii (16bytes)
        hash4 = [hashbin[i:(i + 8)] for i in range(0, len(hashbin), 8)]
        hashascii = ''.join([chr(int(i, 2)) for i in hash4])
        hasharray.append(hashascii)
    return hasharray  # return an array of all your hash values


# encrypting function takes in the key and plaintext inputted from the user.
def RC4(key, plaint):
    state = list(range(256))
    encryptedlist = []
    length = len(plaint)

    #RC4 - KSA and PRGA
    S = KSA(state, key)
    Ret = PRGAe(S, length)

    for c in plaint:
        m = ord(c) ^ next(Ret)  # xor with the plaintext and keystream
        encryptedlist.append(m)
    return encryptedlist


# decrypting function takes in the key and ciphertext
def decrypt(key, ciphertext):
    state = list(range(256))
    decryptedlist = []
    length = len(ciphertext)

    # RC4 to decrypt
    S = KSA(state, key)
    Ret = PRGAe(S, length)

    for c in ciphertext:
        a = (c) ^ next(Ret) # xor with the ciphertext and keystream
        t = chr(a)  # convert to string
        decryptedlist.append(t)
    return decryptedlist

# function to compare hash values
def comparehashfunction (decryptedlist, offset):
        plaintextlist = []
        hashvaluelist = []
        scplaintextlist = []
        for i in decryptedlist:
            n = i[-16:]  # stripping off the hashvalue from the decrypted text
            hashvaluelist.append(n)
            m = i[:252]  # taking the plain text
            plaintextlist.append(m)

        for j in range(len(plaintextlist)):
            sc = "{0:0>4}".format(j)  # generating SCb
            scplaintext = str(sc) + str(plaintextlist[j])
            scplaintextlist.append(scplaintext)

        split64 = split2(scplaintextlist) # splitting the decrypted text into 64 bytes for the hash function
        hashlist = hash(split64, int(offset))  # performing the hash calculation

        if hashvaluelist == hashlist:
            print(color.BOLD + color.YELLOW + "*   SENDER AND RECEIVER'S HASH VALUES ARE EQUAL!!!" + color.END)
        else:
            print(color.BOLD + color.RED + "Your packet has been corrupted!!!! Or you have entered a different key and offset value from the user. Please confirm" + color.END)

        return hashlist

# main function
if __name__ == '__main__':
    #a class to give colours to the output
    class color:
        PURPLE = '\033[95m'
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        END = '\033[0m'

    encryptedlist = []
    decryptedlist = []

    #Getting input from user

    print(color.BOLD + "**************************************************************************************************************************************************************************************************************")
    print(color.BOLD + "\n************************************************" + color.END)
    print(color.PURPLE + color.BOLD + "*                        SENDER                *"+color.END)
    print(color.BOLD + "************************************************" + color.END)
    initialplaintext = input(color.BOLD + "*   PLEASE TYPE IN YOUR PLAIN TEXT: " + color.END)
    senderoffset = int(input(color.BOLD + "*   ENTER YOUR OFFSET VALUE: " + color.END))
    senderkey = input(color.BOLD + "*   ENTER YOUR KEY: " + color.END)

    # splitting plaintext into 252 bytes
    plaintext, plainSC, diff = splitmessage(initialplaintext)

    print(color.BOLD + "\n*   LENGTH OF DATA: " + color.END, len(initialplaintext), "bytes")
    print(color.BOLD + "*   NUMBER OF PACKETS: "+ color.END, len(plaintext))

    # splitting further into 64 bytes
    b = split2(plainSC)

    # performing the hash function for the sender
    a = hash(b, int(senderoffset))
    print(color.BOLD + "*\n   These are your hash values" + color.END)
    for i in a:
        print(color.BOLD + "*   HASH" + color.BOLD + "|" + color.END, i)
    print(color.BOLD + "\n**************************************************************************************************************************************************************************************************************")


    print(color.BOLD + "\n\n************************************************" + color.END)
    print(color.BOLD + color.GREEN + "*                     RECEIVER                 *" + color.END)
    print(color.BOLD + "************************************************" + color.END)
    receiveroffset = input(color.BOLD + "*   ENTER YOUR OFFSET VALUE. \n*   Please enter same offset number with the sender: " + color.END)
    receiverkey = input(color.BOLD + "*   ENTER YOUR KEY \n*   Please enter same secret key with the sender: "+ color.END)

    for i in range(len(plaintext)):
        hashplaintext = plaintext[i] + a[i]
        result1 = RC4(senderkey, hashplaintext)
        encryptedlist.append(result1)

    for i in range(len(encryptedlist)):
        result2 = decrypt(receiverkey, encryptedlist[i])
        x = str.join('', result2)
        decryptedlist.append(x)

    #ciphertexts in ascii
    asciilist = []
    for i in encryptedlist:
        for j in i:
            asciilist.append(chr(j))
    #print("".join(i for i in asciilist))

    print(color.BOLD + "\n*\n*   Compare hash values to be sure your packets are not compromised\n" + color.END)
    v = comparehashfunction(decryptedlist, receiveroffset)
    print(color.BOLD + "*   Receiver's hash value", "\n" + color.END)
    for i in v:
        print(color.BOLD + "*   HASH", "|" + color.END, i)

    # remove hash and padding from decrypted text
    remhash = []
    unpaddeddecrypted = decryptedlist
    for i in unpaddeddecrypted:
        m = i[:252]
        remhash.append(m)

    lastpadding = remhash[len(remhash)-1]
    rempadding = lastpadding[:-int(diff)]

    remhash[len(remhash)-1] = rempadding
    #printing the decrypted text
    decryptedtext = ''.join(remhash)
    print("*\n")
    print(color.BOLD + color.UNDERLINE + "*   THIS IS YOUR DECRYPTED TEXT" + color.END, "\n*  ", decryptedtext)
    print("\n\n**************************************************************************************************************************************************************************************************************")





