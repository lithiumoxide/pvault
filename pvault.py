#!/usr/bin/env python3

import base64
import os
import sys
import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as pbk

vaultfile = 'vault.pv'

def generate_key_from_password(vault_password):
	encoded_vault_password = vault_password.encode()
	salt = b'salt_'
	kdf = pbk(
		algorithm = hashes.SHA256(),
		length = 32,
		salt = salt,
		iterations = 100000,
		backend = default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(encoded_vault_password))

	return key

def encrypt(vault_password, str_to_encrypt):
	fernet = Fernet(generate_key_from_password(vault_password))
	encrypted_str = fernet.encrypt(str_to_encrypt.encode())

	return encrypted_str

def decrypt(vault_password, str_to_decrypt):
	fernet = Fernet(generate_key_from_password(vault_password))
	decrypted_str = fernet.decrypt(str_to_decrypt.encode())

	return decrypted_str

def list_entries():
	with open(vaultfile, 'r') as vault:
		for line in vault:
			seperated_line = line.split(',')
			print(seperated_line[0])

def add_to_vault():
	alias = input('Alias: ')
	username = input('Username: ')
	password = getpass.getpass(prompt = 'Password: ')
	vault_password = getpass.getpass(prompt = 'Vault password: ')

	encrypted_username = encrypt(vault_password, str_to_encrypt=username)
	encrypted_password = encrypt(vault_password, str_to_encrypt=password)

	line_for_storage = alias + ',' + str(encrypted_username)[2:-1] + ',' + str(encrypted_password)[2:-1] + '\n'

	with open(vaultfile, 'a+') as vault:
		vault.write(line_for_storage)
	vault.close()

def retrieve_from_vault():
	alias = input('Alias: ')
	vault_password = getpass.getpass(prompt = 'Vault password: ')

	with open(vaultfile, 'r') as vault:
		for line in vault:
			if alias in line:
				seperated_line = line.split(',')
				encrypted_username = seperated_line[1]
				encrypted_password = seperated_line[2]

				try:
					decrypted_username = decrypt(vault_password, str_to_decrypt=encrypted_username)
					decrypted_password = decrypt(vault_password, str_to_decrypt=encrypted_password)
					print('Username: ' + str(decrypted_username)[2:-1])
					print('Password: ' + str(decrypted_password)[2:-1])
				except:
					print('Decryption failed. Please check your vault password.')

			else:
				pass

def main(*args):
	if len(sys.argv) > 1:
		if sys.argv[1] == 'add':
			add_to_vault()
		elif sys.argv[1] == 'retrieve':
			retrieve_from_vault()
		elif sys.argv[1] == 'list':
			list_entries()
		else:
			print('Use: add, retrieve, list')
	else:
		print('Use: add, retrieve, list')

main()
