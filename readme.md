## Dependencies
- `pip install pycryptodome`
- `pip install sympy`

# How to use
- When you run `cryptomatic.py` a menu is displayed of options you can choose to execute
## Lets go through them:
### Symmetric encryptions
- `[1] ECB encription`
- `[2] ECB decription`
- `[3] CTR encription`
- `[4] CTR decription`
- `[5] AEAD encription`
- `[6] AEAD decription`

All of them have the same pattern of command-line flags:
- `[x] [file_to_en-/decrypt] [password]`

As an example: `2 input.ecb StealthPassword123!`. You always get a note on where your file was saved under what name

### Assymetric encryptions
- `[7] RSA public / private key generation`

Here you just need to choose `7` and your keys are going to be generated. They will be saved in the same directory as you're working now as `public_key.txt` and `private_key.txt`

- `[8] RSA encription`
- `[9] RSA decription`

Here the following pattern of flags is used:

- `[x] [file_to_en-/decrypt] [public/private_key_filepath]`

As an example: `8 input.txt public_key.txt`. You always get a note on where your file was saved under what name.

### Main excercise for assymetric encription
- `[10] Symmetric encryption of file body and assymetric encription of password`

Here the following pattern is used: 
- `[x] [file_to_encrypt] [public_key_filepath] [password]`

As an example: `10 input.txt public_key.txt Admin123!StealthMode`. Here again, you get notified on where the file was saved and where  

- `[11] Decryption of file body with help of private key to decrypt symmetric key`

Here the following pattern is used: 
- `[x] [file_to_decrypt] [private_key_filepath]`

As an example: `11 input.excercise.txt private_key.txt`. You also get notified where and how the file was saved.

# Explanation
## Symmetric encryption's
### ECB
- Pretty straight forward 'Electronic Codebook' algorithm. Password is filled with 0's so it will be 16 bytes long. Then the plaintext is encrypted with the help of the `cryptodome` library.
- The decryption is the same, just in reverse.
### CTR
- Here the 'Counter-Mode' is also filling the password to be 16 bytes long. A counter is created which gets incremented in the background. The nonce I didn't need to create since it is probably also done via the `cryptodome` library.
### AEAD (AES-GCM)
- First a bigger key is derived also by padding 0's and then returning the 32 bit key, which is used to encrypt it via the `cryptodome` library. We get the nonce, the encrypted ciphertext and a tag. The tag is used for authentication and integrity check. These (nonce, tag, ciphertext) are then concatenated and saved as a file.
- To decript it, the encripted file is read, then the nonce, the tag and the ciphertext are split up so they can be used in the decription process.
## Assymetric encription's
### RSA key generation
- First two large prime numbers (p & q) are generated (1024 bits long)
- Then we get phi_n through Eulers Totient function and with this and e (needs to be coprime of phi_n; and either 3 or 65515 because of efficiency) we search for the private exponent d.
- Now we have everything so the `public_key.txt` and the `private_key.txt` can be created
- Attention: sometimes the modular inverse doesn't exist, which then throws an exception. This hasn't been handled, so the script needs to be restarted and then the generation needs to be run again.
### RSA encription
- The plaintext message is converted to an integer representation by switching all the characters into their corresponding ascii value in a padded format, so each ascii value has three digits.
- Then to encrypt the message, we get the modulus and exponent from the `public_key.txt` file and then use the `pow(..)` function to get our encrypted message. This is then saved as a file
### RSA decription
-  To decrypt the file we just read the encrypted file, convert its content into an Integer, then we do the reverse function with the private exponent and thus get our initial plaintext in the form of a sequence of ascii values which need to be converted back into a string.
## Main exercise in assymetric encription
### Encryption
- Here we derive a key from the given password and then we encrypt the plaintext with this key through the AES-GCM methode. We then again concatenate the nonce, tag and ciphertext as our encrypted_data.
- Our given password is changed into it's ascii values, so we can encrypt it via our public key. 
- Now we combine the encrypted passwort (through RSA) and the encrypted plaintext (through AEAD (AES-GCM)) together into one file, which gets saved.
### Decription
- So we can now decript this file, we need to first extract the encrypted password out of it and then decrypt it via private key. Once we have our plaintext password, and once we split up the encrypted file body into nonce, tag and ciphertext, we can easily decrypt the whole thing and get our plaintext back.



