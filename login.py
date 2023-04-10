from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sqlite3
import sys
import os
import base64
from Crypto.Hash import SHA256
from getpass import getpass
import difflib


def get_connection(file):
    try:
        connection = sqlite3.connect(file, check_same_thread=False)
        return connection
    except sqlite3.Error as error:
        print("An error occurred while connecting to database.")

def get_password_by_address(address, master_pass):

    address_sha = SHA256.new(data=bytes(address.strip(), 'utf-8')).digest()
    connection = get_connection('database.db')
    cur = connection.cursor()
    cur.execute("""SELECT * FROM passwords WHERE address = '{a}';""".\
        format(a=base64.b64encode(address_sha).decode('ascii')))
    fetched = cur.fetchall()
    cur.close()
    connection.commit()
    connection.close()

    decoded_salt = base64.b64decode(fetched[0][2])
    key = PBKDF2(master_pass.strip(), decoded_salt, 32, count=1000, hmac_hash_module=SHA512)
    decoded = base64.b64decode(fetched[0][1])
    cipher2 = AES.new(key, AES.MODE_GCM, nonce=decoded[:16])
    decrypted=cipher2.decrypt(decoded[16:]).decode('utf-8')

    if base64.b64decode(decrypted[:44]) != address_sha:
        print("Master password incorrect or integrity check failed.")
        return False
    
    return base64.b64decode(decrypted[47:]).decode('utf-8')

def is_pass_forced(user):
    connection = get_connection('database.db')
    cur = connection.cursor()
    user_sha = SHA256.new(data=bytes(user.strip(), 'utf-8')).digest()
    cur.execute("""SELECT * FROM passwords WHERE address = '{u}';""".\
        format(u=base64.b64encode(user_sha).decode('ascii')))
    fetched = cur.fetchall()
    cur.close()
    connection.commit()
    connection.close()
    return fetched[0][3]

def put_password(master_pass, address, password):
    # check if address already exists. (address is SHA summed and saved to database)
    address_sha = SHA256.new(data=bytes(address.strip(), 'utf-8')).digest()
    # check if address already exists in database:
    connection = get_connection('database.db')
    cur = connection.cursor()
    cur.execute("""SELECT * FROM passwords WHERE address = '{a}'""".\
        format(a=base64.b64encode(address_sha).decode('ascii')))
    fetched = cur.fetchall()
    cur.close()
    connection.commit()
    connection.close()
    # else: put new address and password to database:
    salt = get_random_bytes(16)
    key = PBKDF2(master_pass.strip(), salt, 32, count=1000, hmac_hash_module=SHA512)
    cipher = AES.new(key, AES.MODE_GCM)
    to_encrypt = base64.b64encode(address_sha).decode('ascii') + " : " + base64.b64encode(bytes(password.rjust(256, '\0'), 'utf-8')).decode('ascii')
    ciphertext = cipher.encrypt(bytes(to_encrypt, 'utf-8'))  
    # data to be saved in database: (nonce+ciphertext)
    data = cipher.nonce + ciphertext
    # encode bytes to base64 before saving to database:
    encoded = base64.b64encode(data).decode('ascii')
    # same for the salt that was used for generating key:
    encoded_salt = base64.b64encode(salt).decode('ascii')
    #print("encoded_salt:", encoded_salt)

    connection = get_connection('database.db')
    cur = connection.cursor()

    if len(fetched) != 0:
        # update password for existing address.
        cur.execute("""UPDATE passwords SET password='{p}', salt='{s}' WHERE address = '{q}';""".\
        format(p=encoded, s=encoded_salt, q=base64.b64encode(address_sha).decode('ascii')))
        cur.close()
        connection.commit()
        connection.close()
        print("Password change successful.")
        return
    
    print(f"User {address} successfully added.")
    cur.execute("INSERT INTO passwords VALUES ('{a}','{p}','{s}','{c}')".\
            format(a=base64.b64encode(address_sha).decode('ascii'), p=encoded, s=encoded_salt, c=0))
    cur.close()
    connection.commit()
    connection.close()

def unforce_pass(user):
    connection = get_connection('database.db')
    cur = connection.cursor()
    user_sha = SHA256.new(data=bytes(user.strip(), 'utf-8')).digest()
    cur.execute("""UPDATE passwords SET change_pass='0' WHERE address = '{q}';""".\
        format(q=base64.b64encode(user_sha).decode('ascii')))
    cur.close()
    connection.commit()
    connection.close()
    return

def main():
    master_pass = '123'
    username = sys.argv[1]
    password = getpass("Password:")
    fetched_pass = get_password_by_address(username, master_pass)

    pass_bytes = bytes(password.rjust(256, '\0'), 'utf-8')
    while pass_bytes.decode('UTF-8') != fetched_pass:
        print("Username or password incorrect.")
        password = getpass("Password:")
        pass_bytes = bytes(password.rjust(256, '\0'), 'utf-8')

    if is_pass_forced(username):
        password = getpass("New password:")
        password1 = getpass("Repeat new password:")
        if password != password1:
            print("Password change failed. Password mismatch.")
            exit(0)
        put_password(master_pass, username, password)
        unforce_pass(username)
    
    print("Login successful.")

if __name__ == '__main__':
    main()