from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import re

#  _____ ____ ____
# | ____/ ___| __ )
# |  _|| |   |  _ \
# | |__| |___| |_) |
# |_____\____|____/

'''Encrypts a plaintext using AES encryption in ECB mode.'''
# key needs to be 16 bytes long
def encrypt_aes_ecb(plain_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))

'''Decrypts a cyphertext using AES encryption in ECB mode.'''
def decrypt_aes_ecb(cipher_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(cipher_text), AES.block_size)

def ECB_encrypt(key, plaintext):
    cipher_text = encrypt_aes_ecb(plaintext, key)
    return cipher_text

def ECB_decrypt(key, cipher_text):
    plaintext = decrypt_aes_ecb(cipher_text, key)
    return plaintext.decode('utf-8')

def ECB_encrypt_flow(params):
    file_path = params[1]
    plaintext = extract_text(file_path)
    key = params[2].encode('utf-8').ljust(16, b'\0')
    cipher = ECB_encrypt(key, plaintext)
    save_file(file_path, ".ecb", cipher)
    # print(cipher)

def ECB_decrypt_flow(params):
    file_path = params[1]
    ciphertext = extract_bytes(file_path)
    key = params[2].encode('utf-8').ljust(16, b'\0')
    text = ECB_decrypt(key, ciphertext)
    save_file(file_path, "_decoded.txt.", text)
    # print(text)


#   ____ _____ ____
#  / ___|_   _|  _ \
# | |     | | | |_) |
# | |___  | | |  _ <
#  \____| |_| |_| \_\

def CTR_encrypt(key, plaintext):
    counter = Counter.new(128)
    plaintext_bytes = plaintext.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    cipher_text = cipher.encrypt(plaintext_bytes)
    return cipher_text

def CTR_decrypt(key, cipher_text):
    counter = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(cipher_text)
    return plaintext

def CTR_encrypt_flow(params):
    file_path = params[1]
    plaintext = extract_text(file_path)
    key = params[2].encode('utf-8').ljust(16, b'\0')
    # print(key)
    # print(len(key))
    cipher = CTR_encrypt(key, plaintext)
    save_file(file_path, ".ctr.txt", cipher)
    # print(cipher)

def CTR_decrypt_flow(params):
    file_path = params[1]
    ciphertext = extract_bytes(file_path)
    key = params[2].encode('utf-8').ljust(16, b'\0')
    text = CTR_decrypt(key, ciphertext)
    save_file(file_path, "_ctr_decoded.txt.", text)
    # print(text)

#     _    _____ ____         ____  ____ __  __
#    / \  | ____/ ___|       / ___|/ ___|  \/  |
#   / _ \ |  _| \___ \ _____| |  _| |   | |\/| |
#  / ___ \| |___ ___) |_____| |_| | |___| |  | |
# /_/   \_\_____|____/       \____|\____|_|  |_|

# TODO Maybe remove salt, so handling is a bit easier

def derive_key(password, key_length=32):
    return password.ljust(key_length, b'\0')[:key_length]
def AEAD_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b''):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(associated_data)  # Set the associated data
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return (cipher.nonce, ciphertext, tag)

def AEAD_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b''):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=len(tag))
    cipher.update(associated_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def AEAD_encrypt_flow(params):
    file_path = params[1]
    plaintext = extract_text(file_path)
    password = params[2].encode('utf-8')
    # print(password)
    # print(len(password))
    key = derive_key(password, 32)  # 256-bit key
    nonce, ciphertext, tag = AEAD_encrypt(key, plaintext.encode('utf-8'))
    # print("nonce: ", nonce)
    # print("Ciphertext: ", ciphertext)
    # print("tag: ", tag)

    encrypted_data = nonce + tag + ciphertext
    save_file(file_path, ".aes_gcm.txt", encrypted_data)

def AEAD_decrypt_flow(params):
    file_path = params[1]
    encrypted_data = extract_bytes(file_path)
    password = params[2].encode('utf-8')

    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    key = derive_key(password, 32)  # 256-bit key
    decrypted_text = AEAD_decrypt(key, nonce, ciphertext, tag).decode('utf-8')
    #print(decrypted_text)
    save_file(file_path, ".aes_gcm.decrypted.txt", decrypted_text)

#  ____ _____   __  ____  ____    _
# |  _ \_ _\ \ / / |  _ \/ ___|  / \
# | | | | | \ V /  | |_) \___ \ / _ \
# | |_| | |  | |   |  _ < ___) / ___ \
# |____/___| |_|   |_| \_\____/_/   \_\

from sympy import nextprime
from random import randint

# Generates a random prime number of approximately 'bits' bits.
def generate_large_prime(bits):
    number = randint(2**(bits-2), 2**(bits-1))
    # Find the next prime after the random number
    prime = nextprime(number)
    return prime

def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def write_key_file(n, e, d):
    with open('public_key.txt', 'w') as file:
        # Formatting the Public Key
        public_key_str = f"-----BEGIN RSA PUBLIC KEY-----\n"
        public_key_str += f"Modulus: {n}\n"
        public_key_str += f"Exponent: {e}\n"
        public_key_str += f"-----END RSA PUBLIC KEY-----"
        file.write(public_key_str)

    with open('private_key.txt', 'w') as file:
        # Formatting the Private Key
        private_key_str = f"-----BEGIN RSA PRIVATE KEY-----\n"
        private_key_str += f"Modulus: {n}\n"
        private_key_str += f"Exponent: {d}\n"
        private_key_str += f"-----END RSA PRIVATE KEY-----"
        file.write(private_key_str)


def read_key_file(filepath):
    # Reading keys from files
    with open(filepath, 'r') as file:
        key = file.read()
        #print(key)
        return key

def create_RSA_keys():
    # First we need to choose two big prime numbers p and q
    p = generate_large_prime(1024)  # generates an approximately 1024-bit prime number
    q = generate_large_prime(1024)  # generates an approximately 1024-bit prime number
    #print(p)
    #print(q)

    #Then we calc n which is then used as the modulo number to get the private key
    n = p * q
    # Then we use Eulers Totient function to get phi of n
    phi_n = (p-1) * (q-1)
    # Then we choose an integer e which makes encryption more efficient. e needs to be a coprime of phi_n
    e = 3
    # Now we search for the private exponent d, which is used in the RSA genetarion
    d = modinv(e, phi_n)
    # Now we write the keys into files (ATM unencrypted)
    write_key_file(n, e, d)

def get_RSA_key_numbers(RSA_key_filepath):
    #print("before keys")
    keys = read_key_file(RSA_key_filepath)
    #print("after keys")
    # Regular expressions to find Modulus and Exponent
    modulus_pattern = re.compile(r'Modulus: (\d+)')
    exponent_pattern = re.compile(r'Exponent: (\d+)')
    # Search the strings for the patterns
    modulus_match = modulus_pattern.search(keys)
    exponent_match = exponent_pattern.search(keys)
    #print("modulus_match: ", modulus_match)
    #print("exponent_match: ", exponent_match)
    modulus = int(modulus_match.group(1))
    exponent = int(exponent_match.group(1))
    #print("modulus: ", modulus)
    #print("exponent: ", exponent)
    return modulus, exponent

def RSA_encrypt_decrypt(key_filepath, message):
    n, e_d = get_RSA_key_numbers(key_filepath)
    result = pow(message, e_d, n)
    #print("Result: ", result)
    return result

def text_to_int(text):
    #Converts text to an integer by converting each character to its 3-digit ASCII value.
    return ''.join(f'{ord(c):03}' for c in text)


def int_to_text(number_str):
    number_str = str(number_str)

    # Ensure that the string length is a multiple of 3 by padding with zeros at the front if necessary
    remainder = len(number_str) % 3
    if remainder != 0:
        number_str = number_str.zfill(len(number_str) + 3 - remainder)

    return ''.join(chr(int(number_str[i:i + 3])) for i in range(0, len(number_str), 3))

def RSA_encrypt_flow(params):
    file_path = params[1]
    public_key_filepath = params[2]
    message = extract_text(file_path)

    int_message = int(text_to_int(message))
    #print("Message: ", int_message)
    cipher_text = RSA_encrypt_decrypt(public_key_filepath, int_message)
    save_file(file_path, ".rsa.txt", cipher_text)

def RSA_decrypt_flow(params):
    file_path = params[1]
    private_key_filepath = params[2]
    cypher_text = extract_text(file_path)

    plain_text = RSA_encrypt_decrypt(private_key_filepath, int(cypher_text))
    plain_text = int_to_text(plain_text)
    #print("Message: ", plain_text)
    save_file(file_path, ".rsa_decoded.txt", plain_text)

'''
# Usage:
key = b"q123456789012345"  # Note the b prefix here, which makes this a bytes object.
plaintext = "Hello! How are you over there?"
ciphertext = ECB_encrypt(key, plaintext)
print(ciphertext)

decrypted_text = ECB_decrypt(key, ciphertext)
print(decrypted_text)

'''


#  _   _      _
# | | | | ___| |_ __   ___ _ __ ___
# | |_| |/ _ \ | '_ \ / _ \ '__/ __|
# |  _  |  __/ | |_) |  __/ |  \__ \
# |_| |_|\___|_| .__/ \___|_|  |___/
#              |_|


def extract_text(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            text = file.read()
            #print("Text from the file:")
            #print(text)
            return text
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def extract_bytes(file_path):
    try:
        with open(file_path, 'rb') as file:
            text = file.read()
            #print("Text from the file:")
            #print(text)
            return text
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def save_file(file_path, extension, content):
    output_file_path = file_path.split('.')[0] + extension

    try:
        if isinstance(content, bytes):
            # Write the byte code to the output file
            with open(output_file_path, 'wb') as output_file:
                output_file.write(content)
                print(f"Byte code written to '{output_file_path}'")
        elif isinstance(content, (int, str)):
            # If content is an int, convert it to str before writing
            content_str = str(content) if isinstance(content, int) else content
            with open(output_file_path, 'w') as output_file:
                output_file.write(content_str)
                print(f"Text code written to '{output_file_path}'")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


#  ____ _     ___                 _
# / ___| |   |_ _|   ___ ___   __| | ___
#| |   | |    | |   / __/ _ \ / _` |/ _ \
#| |___| |___ | |  | (_| (_) | (_| |  __/
# \____|_____|___|  \___\___/ \__,_|\___|
#

def display_menu():
    menu_title("Symmetric cipher", 30)
    print("[1] ECB encription")
    print("[2] ECB decription")
    print("[3] CTR encription")
    print("[4] CTR decription")
    print("[5] AEAD encription")
    print("[6] AEAD decription")
    print("[x] [file_to_en-/decrypt] [password] ")
    print("e.g. '2 input.ecb SuperStealthPassword9001!' ")
    menu_title("Asymmetric cipher", 30)
    print("[7] RSA public / private key generation\n")
    print("[8] RSA encription")
    print("[9] RSA decription")
    print("[x] [file_to_en-/decrypt] [public/private_key_filepath]")
    print("e.g. '8 input.txt public_key.txt'")
    menu_title("Requirements for excercise", 30)
    print("[10] Symmetric encryption of file body and assymetric encription of password")
    print("[x] [file_to_encrypt] [public_key_filepath] [password]")
    print("e.g. '10 input.txt public_key.txt Admin12345!_is_really_stealth_actually'\n")
    print("[11] Decryption of file body with help of private key to decrypt symmetric key")
    print("[x] [file_to_decrypt] [private_key_filepath]")
    print(30 * "~")


def center_string(string, width):
    left = right = int((width - len(string) - 1)/2) * "~"
    string = left + " " + string + " " + right
    if len(string) % width == 1:
        string = string[:-1]
    return string

def menu_title(title, width):
    print(width * "~")
    print(center_string(title, width))
    print(width * "~")

def main():
    while True:
        display_menu()
        choice = input("Enter your choice: ")

        params = choice.split()

        if params[0] == "1": #ECB encription
            ECB_encrypt_flow(params)
        elif params[0] == "2": #ECB decription
            ECB_decrypt_flow(params)
        elif params[0] == "3": #CTR encription
            CTR_encrypt_flow(params)
        elif params[0] == "4": #CTR decription
            CTR_decrypt_flow(params)
        elif params[0] == "5": #AEAD encription
            AEAD_encrypt_flow(params)
        elif params[0] == "6": #AEAD decription
            AEAD_decrypt_flow(params)
        elif params[0] == "7": #RSA public / private key generation
            create_RSA_keys()
        elif params[0] == "8": #RSA encription
            RSA_encrypt_flow(params)
        elif params[0] == "9": #RSA decription
            RSA_decrypt_flow(params)
        elif params[0] == "10": #Asymmetric encryption as needed to be done in excercise

            file_path = params[1]
            public_key_filepath = params[2]
            plaintext = extract_text(file_path)
            password = params[3].encode('utf-8')
            key = derive_key(password, 32)  # 256-bit key
            nonce, ciphertext, tag = AEAD_encrypt(key, plaintext.encode('utf-8'))
            encrypted_data = nonce + tag + ciphertext

            int_password = int(text_to_int(password.decode('utf-8')))
            #print("int password: ", int_password)
            cipher_text = RSA_encrypt_decrypt(public_key_filepath, int_password)

            encripted_file_with_encripted_password = str(cipher_text).encode('utf-8') + b'\n' + encrypted_data
            save_file(file_path, ".excercise.txt", encripted_file_with_encripted_password)



            #"[file_to_encrypt][public_key_filepath][password]"
        elif params[0] == "11":  # Asymmetric decryption as needed to be done in excercise

            file_path = params[1]
            private_key_filepath = params[2]
            plaintext = extract_bytes(file_path)
            #print(plaintext)

            encoded_password_bytes, encrypted_data = plaintext.split(b'\n', 1)
            encoded_password = int(encoded_password_bytes.decode('utf-8'))

            decoded_password = RSA_encrypt_decrypt(private_key_filepath, encoded_password)
            decoded_password = int_to_text(decoded_password)

            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]

            key = derive_key(decoded_password.encode('utf-8'), 32)  # 256-bit key

            decrypted_text = AEAD_decrypt(key, nonce, ciphertext, tag).decode('utf-8')
            #print(decrypted_text)
            save_file(file_path, ".exercise_decripted.txt", decrypted_text)

        else:
            print("Invalid choice. Please try again.")
#11 input.excercise.txt private_key.txt

if __name__ == "__main__":
    main()