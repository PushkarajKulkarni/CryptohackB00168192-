import requests
import hashlib
from Crypto.Cipher import AES

# request encrypted flag
r = requests.get('http://aes.cryptohack.org/passwords_as_keys/encrypt_flag/')
res = bytes.fromhex(r.json()['ciphertext'])
# print(res)

# brute forcing the key to find the plaintext, yes i did it! :D
# i am not bruteforcing to cryptohack website, i do it locally
with open('Tugas5/words', 'r') as f:
    for words in f:
        words = words.strip()

        key = hashlib.md5(words.encode()).digest()

        

        
        cipher = AES.new(key, AES.MODE_ECB)
        res1 = cipher.decrypt(res)
        print(res1)
        if res1.startswith('crypto{'.encode()):
            print(res1)
            print(words)
            break