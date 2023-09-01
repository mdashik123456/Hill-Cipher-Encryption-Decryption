import numpy as np
from sympy import Matrix
from os import system
import platform


alphabet_len = ord('Z') - ord('A') + 1

#Function to clear console display
def clear_display():
    if platform.system() == "Windows":
        system("cls")
    else:
        system("clear")


#Encryption--------------------------------------------------------------------------------------------
def text_to_numbers(text):
    return [ord(char) - ord('A') for char in text] #ord() function return ASCII value of the char


def numbers_to_text(numbers):
    return ''.join([chr(number + ord('A')) for number in numbers])


def encode_hill_cipher(plaintext, key_matrix):
    plaintext = plaintext.replace(" ", "").upper()
    key_matrix = np.array(key_matrix)
    
    block_size = key_matrix.shape[0]
    ciphertext = []

    numerical_values = text_to_numbers(plaintext)
    

    # Pad the plaintext with 'X' if its length is not a multiple of the block size
    while len(numerical_values) % block_size != 0:
        numerical_values.append(ord('X') - ord('A'))

    # Encrypt the message block by block
    for i in range(0, len(numerical_values), block_size):
        block = numerical_values[i:i + block_size]
        block = np.array(block)
        encrypted_block = np.dot(key_matrix, block) % alphabet_len
        ciphertext.extend(encrypted_block)

    return numbers_to_text(ciphertext)



#Decryption--------------------------------------------------------------------------------------------
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return 0

def inverse_key_matrix(key_matrix):
    det = int(round(Matrix(key_matrix).det()))  # Calculate the determinant of the key matrix
    
    if det <= 0:
        print("\nYour Matrix Determinant is 0 or negetive value So...")
        print("!! Decryption Maybe Wrong !!\n")
    
    det_inverse = mod_inverse(det, alphabet_len)  # Calculate the modular multiplicative inverse of the determinant

    adjugate = np.array(Matrix(key_matrix).adjugate())
    inverse_matrix = (det_inverse * adjugate) % alphabet_len
    return inverse_matrix

def decode_hill_cipher(ciphertext, key_matrix):
    ciphertext = ciphertext.replace(" ", "").upper()
    key_matrix = np.array(key_matrix)
    inverse_matrix = np.array(inverse_key_matrix(key_matrix))
    block_size = key_matrix.shape[0]
    plaintext = []

    numerical_values = text_to_numbers(ciphertext)

    # Decrypt the message block by block
    for i in range(0, len(numerical_values), block_size):
        block = numerical_values[i:i + block_size]
        block = np.array(block)
        decrypted_block = np.dot(inverse_matrix, block) % alphabet_len
        plaintext.extend(decrypted_block)

    return numbers_to_text(plaintext)



while True:
    clear_display()
    choice = input("Type 'encode' to encrypt\nType 'decode' to decrypt\n==> ")
    if choice == "encode" or choice == "decode":
        text = input("Type your messege : ")
        matrix_block_size = int(input("Enter Matrix Size (EX: for for '2X2 input 2' | '3X3 input 3'...): "))
        
        key_matrix = []
        tmp_mat = []
        for row in range(matrix_block_size):
            for col in range(matrix_block_size):
                tmp_mat.append(int(input(f"Enter Data for [{row}][{col}]: ")))
            key_matrix.append(tmp_mat)
            tmp_mat = []
        
        
        if choice == "encode":
            ciphertext = encode_hill_cipher(text, key_matrix)
            print("\nCipher Text:", ciphertext)
        else:
            plaintext = decode_hill_cipher(text, key_matrix)
            while plaintext[-1] == 'X':
                plaintext = plaintext[:-1]
            print("\nDecrypted Plaintext:", plaintext)
        
    else:
        print("\nWrong Selection\nYou need to type 'encode' to encrypt or 'decode' to decrypt\n")

    isContinue = input("Do you want to continue? (Y/N) : ")
    clear_display()
    if isContinue == 'n' or isContinue == 'N': break
    
print("\n\n---------------------------------------------------")
print("\nGoodbye\nThanks for using....")
print("---------------------------------------------------")




