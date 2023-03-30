# DaVinciCTF 2023 — Pwn Write-up : Robots out of control

From Saturday, March 11 to Sunday, March 12, 2023, the DaVinci CTF was organized by the students of the Pôle Léonard de Vinci. Our team finished 10th overall out of 289 teams.


![](./data/dvinci.png)

Let’s go for a writeup of the Robots out of control challenge in Pwn category.

Thanks to the DaVinciCode team for creating this challenge and managing the CTF!

```
One of our warriors robot (called eva) has been corrupted by an unknow enemy. We have lost the control and he is now in berserk mode. Hopefully we have developped a rescue terminal in case some issue happen. You have to disable the berserk mode through the terminal, you can use all techniques you want. Here is the binary

nc pwn.dvc.tf 8889 
```

files: [robotsoutofcontrol.tgz](./robotsoutofcontrol.tgz)

## Analysis

This time we are simply given the ELF (and the Dockerfile?) and have to find the vulnerability ourselves.

```
$ ./vuln 
	EVA remote rescue terminal
		A. Exit
		B. Drop emergency shell
		C. New command stub
		D. Edit command stub
		E. Print command stub
		F. Inject command stub
		G. Print this menu
		NERV. All right reserved
>>
```

We can create, edit, print and inject "command stubs", that are a struct looking like this, from what I understood:

```c
struct stub {
  char* command_ptr;  // -> stub.command_content
  int command_size;
  char** ramiel_msg = 0x00[]72f0;  // 0x00[]72f0 -> 0x00[]72c0 -> "Damn..."
  int ramiel_size = 0x21;
  char[10] command_content;
}
```

When we create a new command stub, we can specify a command. The code takes only the first 10 chars and put them in `command_content`. The issue is that `command_size` is equal to the size of the string we entered, and not the max size of the `command_content` buffer (10).
So if we enter "AAAAAAAAAAAAAAAAAAAA" (20xA), we will have 10xA in`command_conent` and 0x14 (20) in `command_size`.

This is bad, because the function `edit_command_stub` reads `stub.command_size` chars from the stdin and puts them in `*command_ptr`, creating a heap overflow.

## The heap overflow

When we create 2 stubs, here's the state of the heap:
```
stub0:             0x555582c0    0x00005555
				   0x00000123    0x00000000
				   0x555572f0    0x00005555
                   0x00000021    0x00000000
				   0x41414141    0x41414141
				   0x41414141    0x00414141

dontcare:          0x00000000    0x00000000
				   0x00000021    0x00000000

stub1:             0x55558300    0x00005555
				   0x00000123    0x00000000
				   0x555572f0    0x00005555
				   0x00000021    0x00000000
			       0x42424242    0x42424242
                   0x42424242    0x00424242
```

(Note that both stub have a `command_size` of 0x123, so we can trigger the overflow)

Now, if we edit stub0 and write something like 48xA, we now have:

```
stub0:             0x555582c0    0x00005555
				   0x00000123    0x00000000
				   0x555572f0    0x00005555
                   0x00000021    0x00000000
				   0x41414141    0x41414141
				   0x41414141    0x00414141

dontcare:          0x41414141    0x41414141
				   0x41414141    0x41414141

stub1:             0x41414141    0x41414141
				   0x41414141    0x41414141
				   0x5555720a    0x00005555
				   0x00000021    0x00000000
			       0x42424242    0x42424242
                   0x42424242    0x00424242
```

We successefully overwritted pointers of stub1 !
Since we can control the pointers of stub1, we know we have both arbitrary write and arbitrary read thanks to the functions `print_command_stub` and `edit_command_stub` that both uses `stub.command_ptr` to perform.

I was really happy when achieving this, but when trying to exploit it locally nothing worked, I completely forgot that the binary was PIE... Went to sleep sad because I could not think straight.


### Bypass PIE

When explaining where I was to a teammate, we quickly found out how to leak an address in order to bypass PIE, we just had to write until just before the address we want to leak and print the command of stub0, that will print the heap until a null byte, which means leaking an address!

Thanks to that, we can leak the address of the hard coded string "DAMN, we are getting fucked by Ramiel" (who tf is ramiel anyway), and since the string is in the data section, we can retrieve the base address of the binary by substracting it's offset.

### Bypass ASLR

Since we have bypassed PIE, we can now use a ret2plt attack in order to leak and address of a LIBC function and retrieve the base address of LIBC with the same process for the PIE bypass. 
Since I know the base address of the binary, I also know where the GOT segment is, so I made another heap overflow, since time overwritting the value of `stub.command_ptr` with the address of `got.puts`. Then we simply need to call `print_command_stub` on the stub, and this will leak the content of `got.puts`, which is the address of the libc puts in the memory (where libc has been mapped). Since the version of libc is not known, we also have to find the version by leaking 2 other functions, and going to a site like [this one](https://libc.rip/) in order to get the version of libc and the interesting offset (the offset of puts in order to calculate libc base address and the offset of system to our ret2libc attack)

### Ret2libc

Now, it's a simple ret2libc attack: since I already have an arbitrary write, I just have to replace the address of `got.puts` to the address of system, that we can calculate since we have bypassed ASLR.

Once, we did that, we just have to write "/bin/sh" as the `command_content` of a stub, and when we'll `print_command_stub` on it, it will execute `system("/bin/sh")` :)


### Conclusion

My entire exploit code is [here](./exploit.py)

```
$ python3 exploit.py
[*] '/home/gammray/Documents/CTF/dvctf/pwn/robot_out_of_control/vuln'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.dvc.tf on port 8889: Done
[*] Creating attacking stub n°0 with max command size of 512
[*] stub n°0 created
[*] Creating attacking stub n°1 with max command size of 512
[*] stub n°1 created
[*] Editing stub n°0
[*] stub n°0 edited
STUB ADDR        :  0x55c44a3a32f0
BASE ADDR OFFSET :  0x6ef4e4c000
PUTS GOT ADDR    :  0x55c44a3a3220
[*] Creating attacking stub n°3 with max command size of 512
[*] stub n°3 created
[*] Creating attacking stub n°4 with max command size of 512
[*] stub n°4 created
[*] Editing stub n°3
[*] stub n°3 edited
LIBC PUTS        :  0x7ffa23cc4ed0
LIBC BASE ADDR   :  0x7ffa23c40000
SYSTEM ADDR      :  0x7ffa23c94d60
[*] Creating attacking stub n°9 with max command size of 512
[*] stub n°9 created
[*] Creating attacking stub n°10 with max command size of 512
[*] stub n°10 created
[*] Editing stub n°9
[*] stub n°9 edited
[*] Editing stub n°10
[*] stub n°10 edited
[*] Creating attacking stub n°11 with max command size of 512
[*] stub n°11 created
[*] Switching to interactive mode
Enter the index of your command stub (should be in range 0,255 included)
>>sh: 1: Start: not found
$ ls
flag
run
```