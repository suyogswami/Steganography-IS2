#-------------------------------------------------------------------------------------------------------------------------------------------
# Name:        Steganography - Embed text message inside an image (FInal Project for Information Security 2)
# Author:      Suyog S Swami
# Students ID:   1001119101
#
# Please open the editor in full screen to view all the comments on right side of each line.
# The code is extension of RSA implementation we did during our programming assignmnent 2.
#-------------------------------------------------------------------------------------------------------------------------------------------
from __future__ import print_function
import copy
import random
from PIL import Image
import numpy as np
import textwrap
#Check the comments and citations on the right side of each line. The total references are listed at the end of the code.

def generatekey(bignumber1,bignumber2):                                         #This function is used to generate the public key, priate key and
    p = selectPrimeBetween(bignumber1,bignumber2)                               # n. The input is two big numbers which are used to generate p and q.
    q = selectPrimeBetween(bignumber1,bignumber2)
    if q == p:                                                                  #if p and q are same , again calculate q such that thet are not equal.
        q = selectPrimeBetween(bignumber1,bignumber2)
    n = p * q                                                                   #calculate n
    phi_n = (p - 1) * (q - 1)                                                   #calculate phi of n
    while True:
        e = random.randint(1, phi_n)                                            #chocse e as a random number between 1 and phi of n and check if it is
        if isRelativelyPrime([e, phi_n]):                                       #relatively prime with phi of n.
            break
    d = modInverseUsingExtendedEuclid(e, phi_n)                                 #calculate d using the extended euclidean algorithm.
    return (n, e, d)

def selectPrimeBetween(bignumber1,bignumber2):                                  #This function is used to calculate prime numbers and check wheather they
    x = random.randint(bignumber1,bignumber2)                                   # prime using Miller Rabins Primality test.
    for i in range(0, 1500):                                                    #the 1500 in range was hardcoded after testing for the for loop.
        if checkPrime(x):
            return x
        else:
            x = random.randint(bignumber1,bignumber2)                           #if the choosen number isnt prime randomly choose another number.

def isRelativelyPrime(list_e_phin):                                             #Function to check wheather the e and phi of n are relatively prime or not
    m=list_e_phin[0]
    n=list_e_phin[1]
    if euclideanToFindGCD(m, n) != 1:                                           #if the gcd value from calulation of euclidean algo is not 1 then the numbers
        return False                                                            # are not relatively prime.
    return True

def modInverseUsingExtendedEuclid(e,phi_n):                                     #Extended euclidean algo is used to calculate the modular inverse of e. i.e
    temp = 0                                                                    #d = e(inverse) mod(phi of n)
    newtemp = 1                                                                 # I have used wikipedias extended euclid pseudocode as a reference.
    remainder = phi_n                                                           # But this code is my own version.
    newremainder = e                                                            #http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
    while (newremainder != 0):
        quotient = remainder // newremainder
        x=temp
        y=newtemp
        temp=newtemp
        newtemp=x - quotient * y
        o=remainder
        p=newremainder
        remainder=newremainder
        newremainder=o - quotient * p
    if remainder > 1 :
        raise ValueError("e={} is not invertible".format(e))
    if temp < 0 :
        temp = temp + phi_n                                                     #If the value of temp is negative then add the phi of n to it to get the d.
    return temp

def checkPrime(x):                                                              #This is my own version of implementation of Miller Rabin Primality Test.
    k_for_accuracy=50                                                           #I have used the the example in "Cryptography and Network Security Principle
    if x>=2:                                                                    # and practice 6th edition" , page 692-693 and the algotithm of Miller Rabin
        if x % 2 == 0:                                                          # primality test from wikipedia as refernce.
            return False                                        #http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Algorithm_and_running_time
        if x == 2:
            return True
        k = 0
        q = x-1
        while True:
            quo = q//2
            rem = q%2
            if rem == 1:
                break
            k = k+1
            q = quo
        if (2**k * q == x-1):                                                   #finding and checking k and q such that 2**k*q=n-1
            for i in range(k_for_accuracy):                                     #k_for_accuracy is selected as 50 as per the discussions on piazza.
                a = random.randrange(2, x)
                if checkComposite(a,q,x,k):                                     # call to function to check if x is composite or not.
                    return False
    return True

def checkComposite(a,q,x,k):                                                    #This is again my version of code with the refence of miller rabin pseudocode on
    if fastModularExponentiation(a, q, x) == 1:                                 #wikipedia.
        return False                                            #http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Algorithm_and_running_time
    for i in range(k):
        if fastModularExponentiation(a, 2**i * q, x) == x-1:                    #Here i am using Fast Mod Exponentiation to check if number is composite or
            return False                                                        # not
    return True

def euclideanToFindGCD(m, n):                                                   #Here i am calculating the gcd using the euclidean algorithm.
    if m < n:
        p = m
        m=n
        n=p
    while n != 0:
        p=m%n
        m= n
        n=p
    return m

def fastModularExponentiation(a, b, n):                                         # Here i am using the fast modular exponentiation.
    Bnum = int2baseTwo(b)                                                       #the code is same as that in book "Cryptography and Network Security Principle"
    c=0                                                                         # and practices 6th edition." page 269.
    f=1
    for i in range(len(Bnum)-1,-1,-1):
        c=c*2
        f=(f*f)%n
        if Bnum[i]==1:
            c=c+1
            f=(f*a)%n
    return f

def encrypt(message, modN, e, blockSize):
    numList = string2numList(message)
    numBlocks = numList2blocks(numList, blockSize)
    ciphertext=[]
    for block in numBlocks:
        cphrtxt=fastModularExponentiation(block, e, modN)                       #For each block of message, cipher text is computed  using modular Exponentiation
        ciphertext.append(cphrtxt)
    return ciphertext

def decrypt(secret, modN, d, blockSize):
    numBlocks = []
    for block in secret:
        numblck=fastModularExponentiation(block,d,modN)                         #For each block of ciphertext, message is computed  using modular Exponentiation
        numBlocks.append(numblck)
    numList = blocks2numList(numBlocks, blockSize)
    return numList2string(numList)

#The functions below are not changed as they were present in the rsafillin code give by Prof. Matthew Wright.

def extractTwos(m):
    assert m >= 0
    i = 0
    while m & (2 ** i) == 0:
        i += 1
    return i, m >> i

def int2baseTwo(x):
    assert x >= 0
    bitInverse = []
    while x != 0:
        bitInverse.append(x & 1)
        x >>= 1
    return bitInverse

def string2numList(strn):
    return [ord(chars) for chars in strn]

def numList2string(l):
    return ''.join(map(chr, l))

def numList2blocks(l, n):
    returnList = []
    toProcess = copy.copy(l)
    #print(len(toProcess))
    if len(toProcess) % n != 0:
        for i in range(0, n - len(toProcess) % n):
            toProcess.append(random.randint(32, 126))
        #print(toProcess)
    for i in range(0, len(toProcess), n):
        block = 0
        for j in range(0, n):
            block += toProcess[i + j] << (8 * (n - j - 1))
        returnList.append(block)
    return returnList

def blocks2numList(blocks, n):
    toProcess = copy.copy(blocks)
    returnList = []
    for numBlock in toProcess:
        inner = []
        for i in range(0, n):
            inner.append(numBlock % 256)
            numBlock >>= 8
        inner.reverse()
        returnList.extend(inner)
    return returnList

if __name__ == '__main__':
    bignumber1=5**50                                                            #selected 2 large numbers for generating randum prime p and q between the range
    bignumber2=5**70                                                            #of the large numbers.
    (n, e, d) = generatekey(bignumber1,bignumber2)
    message = """
    This is an implementation of Steganography- Embed text message inside an image
        
                                                           -By Suyog Swami(1001119101)     
    """
    
    print('Message to be encrypted and embedded inside the image')
    print(message)                                                              #Message to be encrypted and embedded inside the image
    cipher = encrypt(message, n, e, 15)
    print('Encrypted Message to be emebedded into the image\n')
    print(cipher)                                                               #This Cipher Text is embedded in the image

    im=Image.open("tajmahal.jpg")       #"6.png"                               #Image used for embedding text message
    im.show()
    r, g, b = np.array(im).T                                                    #Image pixel data stored in numpy under 3 coordinates i.e. RGB
    strng=[]
    leng_str=[]

    for i in cipher:                                                            #converting the ciphertext in list form to a single string
        leng_str.append(len(str(i)))
        strng.append(str(i))
    strngs=''.join(strng)
    k=0
    small_str_list=[]

    while k < len(strngs):                                                      #converting each digit into its 6bit binary value and storing it into a list
        small_str=format(int(strngs[k]),'#08b')[2:]
        small_str_list.append(small_str)
        k=k+1
    m=0

    for i in range(int(im.size[0]/2),im.size[0]-1):                             #Inserting ciphertext inside the image
        for j in range(int(im.size[1]/2),im.size[1]-1):
            if m <len(small_str_list):
                bitss=textwrap.wrap(small_str_list[m],2)                        #textwrap is used to group the six bit binary into 3 groups of 2 bits each

                rr=textwrap.wrap(str(format(int(r[i][j]),'#010b')[2:]),2)       #Converting the pixel R value to 8 bit binary
                rr[3]=bitss[0]                                                  #changing the last bit is R with first 2 LSBs of messages binary number.
                r[i][j]=int(''.join(rr),2)                                      #converting binary to integer which will form R value of new image

                gg=textwrap.wrap(str(format(int(g[i][j]),'#010b')[2:]),2)       #Same procedure as above for G value of the pixel
                gg[3]=bitss[1]
                g[i][j]=int(''.join(gg),2)

                bb=textwrap.wrap(str(format(int(b[i][j]),'#010b')[2:]),2)       #Same procedure as above for B value of the pixel
                bb[3]=bitss[2]
                b[i][j]=int(''.join(bb),2)

                m=m+1
            else:
                break

    grp_cip_lis=textwrap.wrap(format(len(leng_str),'#08b')[2:],2)               #As the cipher text is a list we store the length the list at top right.

    r1=textwrap.wrap(str(format(int(r[im.size[0]-1][0]),'#010b')[2:]),2)        #the code here does the same , i.e. converting RGB pixel values to binar and replacing the LSBs with the list length
    r1[3]=grp_cip_lis[0]
    r[im.size[0]-1][0]=int(''.join(r1),2)

    g1=textwrap.wrap(str(format(int(g[im.size[0]-1][0]),'#010b')[2:]),2)
    g1[3]=grp_cip_lis[1]
    g[im.size[0]-1][0]=int(''.join(g1),2)

    b1=textwrap.wrap(str(format(int(b[im.size[0]-1][0]),'#010b')[2:]),2)
    b1[3]=grp_cip_lis[2]
    b[im.size[0]-1][0]=int(''.join(b1),2)


    for x in range(0,len(leng_str)):                                            #here we are storing the length of each number in the cipher text list at the bottom left
        y=im.size[1]-1

        l_b=textwrap.wrap(format(int(leng_str[x]),'#011b')[2:],3)

        rc=textwrap.wrap(str(format(int(r[x][y]),'#011b')[2:]),3)
        rc[2]=l_b[0]
        r[x][y]=int(''.join(rc),2)

        gc=textwrap.wrap(str(format(int(g[x][y]),'#011b')[2:]),3)
        gc[2]=l_b[1]
        g[x][y]=int(''.join(gc),2)

        bc=textwrap.wrap(str(format(int(b[x][y]),'#011b')[2:]),3)
        bc[2]=l_b[2]
        b[x][y]=int(''.join(bc),2)

#Encoding done                                                                  #Encoding done
#Decoding Started                                                               #Decoding Started

    img = Image.fromarray(np.dstack([item.T for item in (r,g,b)]))
    img.save('tajmahal2.jpg')             #"your.png"                                 #this is the text embedded image
    img.show()

    r1, g1, b1 = np.array(img).T                                                #RGB numpy list of the new image
    gap_r_bin_w=textwrap.wrap(format(int(r1[img.size[0]-1][0]),'#010b')[2:],2)  #unwrapping the length if cipher text stored at top right corner
    gap_g_bin_w=textwrap.wrap(format(int(g1[img.size[0]-1][0]),'#010b')[2:],2)
    gap_b_bin_w=textwrap.wrap(format(int(b1[img.size[0]-1][0]),'#010b')[2:],2)
    final_gap=int(str.join('', (gap_r_bin_w[3],gap_g_bin_w[3],gap_b_bin_w[3])),2)   #Joining the 3LSBs of the respective RGB value to form the integer number
    final_coma_str=[]
    for i in range(0,final_gap):                                                #Unwrapping the list element lengths
        j=img.size[1]-1
        coma_r_bin_w=textwrap.wrap(format(int(r1[i][j]),'#011b')[2:],3)
        coma_g_bin_w=textwrap.wrap(format(int(g1[i][j]),'#011b')[2:],3)
        coma_b_bin_w=textwrap.wrap(format(int(b1[i][j]),'#011b')[2:],3)
        final_coma=int(str.join('', (coma_r_bin_w[2],coma_g_bin_w[2],coma_b_bin_w[2])),2)
        final_coma_str.append(final_coma)
    f_total=0

    for f in final_coma_str:
        f_total+=f                                                              #This value gives us the total length of the cipher text (in string form)
    t=0
    final_str=[]
    for i in range(int(img.size[0]/2),img.size[0]-1):                           #go to the center of the image and start extracting the RGB values
        for j in range(int(img.size[1]/2),img.size[1]-1):
            if t<f_total:
                final_r_bin_w=textwrap.wrap(format(int(r1[i][j]),'#010b')[2:],2)
                final_g_bin_w=textwrap.wrap(format(int(g1[i][j]),'#010b')[2:],2)
                final_b_bin_w=textwrap.wrap(format(int(b1[i][j]),'#010b')[2:],2)
                final=int(str.join('', (final_r_bin_w[3],final_g_bin_w[3],final_b_bin_w[3])),2) #Unwrap the 3LSBs to get the cipher text value
                final_str.append(final)
                t=t+1
            else:
                break

    for x in final_str:                                                         #Join the intergers obtained to forma an integer string
        long_str=''.join(str(x))

    i_total=0
    init=0
    str_new=[]
    for i in final_coma_str:                                                    #Form a list from the big string obtained above by clubbing integers as per the cipher text element length.
        i_total+=i
        strng_again=strngs[init:i_total]
        str_new.append(int(strng_again))
        init=i_total

    print('\nMessage Extracted from the image\n')
    print(str_new)                                                              #This is the new cipher text extracted from the image, which is similar to the one embedded into the image.

    final_output=decrypt(str_new,n,d,15)                                        #This cipher text is then sent for decryption in the RSA algorithm
    print('\nDecrypted message\n')
    print(final_output)                                                         #displays the final output fo text message which is same as the original text message.

#References:
#1) Miller Rabin Primality Test: http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Algorithm_and_running_time
#2) Extended Euclidean Algorithm: http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
#3) Cryptography and Network Security Principle and practices 6th edition. page 269(Fast Modular Exponentiation)
#4) Cryptography and Network Security Principle and practices 6th edition. page 692-693.(Miller Rabin Primality Test)
#5) http://www.developer.com/java/ent/article.php/3530866/Steganography-101-using-Java.htm (Inspriation for my algorithm)