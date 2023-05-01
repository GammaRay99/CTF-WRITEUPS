password_enc = b'\x3a\x0e\x24\x12\x34\x05\x44\x23\x27\x43\x53\x53\x20\x47\x05\x13'
username_enc = b'\x16\x13\x1a\x1e\x19'
key = 0x77

username = ""
for el in username_enc:
	username += chr(el ^ key)

password = ""
for el in password_enc:
	password += chr(el ^ key)


print(f"{username} : {password}")

