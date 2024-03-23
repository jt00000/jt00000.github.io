---
layout: page
title: "KalmarCTF 2024 Symmetry 1, 2, 3 [EN]"
date: 2024-03-23 00:00:00 -0000
---

This is a three-part problem using the same binary.

The status of each part are as follows.
- Symmetry 1 (Rev, [Rev, Crypto], 42 solve)
- Symmetry 2 (Crypto, [Crypto, Rev, Pwn], 19 solve)
- Symmetry 3 (Pwn, [Crypto, Rev, Pwn], 13 solve)

This binary implements a simple AES-like encryption process, and can be encrypted as many times as you like.

# Binary overview
## Input
First, enter the number of blocks, then enter the key, shift column, and plaintext. When the block size is `n`, size of all input are `8*n` bytes.

It's a bit confusing, but the key and plaintext are input byte sequences of 8 bytes per block, and the shift sequence is designed to input 16 bytes in units of nibbles (4 bits).

The key and plaintext are later decomposed into nibbles. For example, `0xbeef` is decomposed into `e, f, e, b`.

```c
  do {
    while( true ) {
      printf("Number of blocks: ");
      __isoc99_scanf(&DAT_00102053,&local_4c);
      if (local_4c < 0x65) break;
      puts("That is a bit too much...");
    }
    key_array = calloc((ulong)local_4c,8);
    shift_array = calloc((ulong)local_4c,0x10);
    local_20 = calloc((ulong)local_4c,8);
    local_18 = calloc((ulong)local_4c,8);
    for (block = 0; block < local_4c; block = block + 1) {
      printf("Please provide a key for block %u: ",(ulong)block);
      for (i0 = 0; i0 < 8; i0 = i0 + 1) {
        __isoc99_scanf("%2hhx",(long)key_array + (ulong)(i0 + block * 8));
      }
      for (i1 = 0; i1 < 0x10; i1 = i1 + 1) {
        printf("Please provide shift %u for block %u: ",(ulong)i1,(ulong)block);
        __isoc99_scanf("%2hhx",(long)shift_array + (ulong)(i1 + block * 0x10));
      }
      printf("Please provide plaintext for block %u: ",(ulong)block);
      for (i2 = 0; i2 < 8; i2 = i2 + 1) {
        __isoc99_scanf("%2hhx",(long)plaintext_array + (ulong)(i2 + block * 8));
      }
    }
```

## Encryption
Pseudo python code is the implementation is as follows.

For each block of `plain_text_array`, the transition state is changed using a `shift_array` and `key_array` in each round, and the plaintext is replaced based on this state.

```python
def shift(val, idx):
    if val & 1 == 1:
        return ((((((val >> 1) - (idx >> 1)) * 2) & 0xe) - (idx & 1)) + 1) & 0xf
    else:
        return ((idx & 1) + ((idx >> 1) + (val >> 1)) * 2) & 0xf

randval = [9, 10, 8, 1, 14, 3, 7, 15, 11, 12, 2, 0, 4, 5, 6, 13];

for block in range(blocks):
    block_out = plain_text_array[block:block*8+8]
    for round in range(16):
        for i0 in range(16):
            sbox[randval[i0]] = shift(shift_array[i1], i0);
        for i1 in range(16):
            round_key[sbox[i1]] = block_out[i1];
        for i2 in range(16):
            round_key[i2] = shift(round_key[i2], key_array[i2]);
        for i3 in range(16):
            block_out = sbox[sbox[round_key[i3]]];
    ciphertext_array += block_out
```

Actually, I don't really understand what the `shift` function does. If you enter various values, and if you change the second argument from 0 to 15 for a certain first argument, the output values ​​will come out without overlapping.

# Symmetry 1
Key, shift, and ciphertext pairs are given.

From reversing encryption process, it semms that the replacement can be done by restoring sbox, and restoration can be done from `ciphertext`.

Also, `shift` is a reversible process, and since you know the second argument and the result, you only need to check 16 patterns, and you can easily implement the reverse process and get the answer.

```python
keys=[[2, 3, 3, 5, 3, 3, 1, 4, 1, 1, 3, 3, 1, 2, 2, 0], [5, 1, 5, 4, 7, 3, 2, 0, 0, 1, 7, 1, 0, 6, 2, 7], [2, 6, 6, 0, 5, 6, 5, 1, 6, 4, 7, 1, 1, 7, 3, 1], [4, 3, 0, 5, 2, 0, 4, 2, 7, 7, 7, 1, 1, 1, 7, 5], [1, 0, 0, 0, 4, 5, 3, 6, 3, 4, 7, 6, 4, 0, 1, 2], [5, 5, 7, 1, 3, 1, 7, 6, 6, 3, 1, 1, 2, 4, 6, 7], [2, 6, 2, 4, 1, 6, 0, 3, 7, 0, 6, 3, 0, 6, 7, 3]]
shifts=[[0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0]]
ciphertexts=[[8, 12, 10, 7, 2, 6, 3, 2, 14, 1, 8, 4, 2, 12, 9, 15], [10, 13, 5, 2, 13, 12, 11, 5, 14, 5, 3, 12, 4, 11, 0, 9], [10, 4, 0, 3, 9, 13, 13, 2, 2, 1, 0, 4, 3, 15, 11, 12], [7, 13, 1, 13, 9, 9, 9, 10, 9, 12, 3, 0, 1, 10, 7, 12], [13, 3, 10, 6, 9, 9, 2, 13, 1, 10, 13, 0, 4, 2, 1, 0], [6, 2, 2, 2, 15, 9, 12, 4, 7, 6, 2, 15, 1, 10, 14, 7], [10, 12, 6, 14, 14, 2, 14, 12, 15, 0, 15, 0, 8, 9, 4, 2]]
randarr = [9, 10, 8, 1, 14, 3, 7, 15, 11, 12, 2, 0, 4, 5, 6, 13]

def n2b(nibble):
    out =''
    for i in range(0, len(nibble), 2):
        out += chr(nibble[i]*0x10+nibble[i+1])
    return out

def b2n(by):
    blocks = (len(by) // 8) + 1
    out = []
    tmp = []
    for b in by:
        tmp.append(b >> 4)
        tmp.append(b & 0xf)
        if len(tmp) == 0x10:
            out.append(tmp)
            tmp = []
    if tmp != []:
        while(len(tmp) < 0x10):
            tmp.append(0)
        out.append(tmp)
    return out

def shift(val, idx):
    if val & 1 == 1:
        return ((((((val >> 1) - (idx >> 1)) * 2) & 0xe) - (idx & 1)) + 1) & 0xf
    else:
        return ((idx & 1) + ((idx >> 1) + (val >> 1)) * 2) & 0xf

def invshift(shifted, idx):
    for i in range(0x10):
        ret = shift(i, idx)
        if ret & 0xf == shifted:
            return i
    assert False, "something wrong"

def get_nibble(buf, idx):
    return buf[idx]

def set_nibble(buf, idx, val):
    buf[idx] = val

def reverse(ct, karr= keys, sarr=shifts, nb=0):
    block_out = ct
    round_key = [0] * 0x10

    sboxes = []
    for i in range(0x10):
        sbox = [0] * 0x10 
        for j in range(0x10):
            sel = randarr[j] 
            val = shift(sarr[nb][i], j)
            sbox[sel] = val
        sboxes.append(sbox)

    for rnd in range(0x10):
        sbox = sboxes[0xf-rnd]
        round_key = [0] * 0x10

        for i3 in range(0x10):
            val1 = get_nibble(block_out, i3)
            val2 = sbox.index(sbox.index(val1))
            set_nibble(round_key, i3, val2)
 
        for i2 in range(0x10):
            val1 = get_nibble(karr[nb], i2)
            val2 = get_nibble(round_key, i2)
            val3 = invshift(val2, val1)
            set_nibble(round_key, i2, val3)
 
        for i1 in range(0x10):
            val1 = get_nibble(round_key, sbox[i1]) 
            set_nibble(block_out, i1, val1)

    return block_out

flag = ''
for i, c in enumerate(ciphertexts):
    flag += n2b(reverse(c, nb=i))
print(flag)
```

`kalmar{nice!_now_please_try_the_other_two_parts}`

# Symmetry 2
The main category of this task is `Crypto`. (For me, I didn't find much Crypto elements.)

You can see that at the beginning of the encryption process, there is a part where the flags are copied onto the stack. I think the purpose of `Symmetry 2` is to output this.

```
        0010160b 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
        0010160f 31 c0           XOR        EAX,EAX
        00101611 48 b8 6b        MOV        RAX,0x667b72616d6c616b
                 61 6c 6d 
                 61 72 7b 66
        0010161b 48 ba 61        MOV        RDX,0x67616c665f656b61
                 6b 65 5f 
                 66 6c 61 67
        00101625 48 89 45 90     MOV        qword ptr [RBP + local_78],RAX
        00101629 48 89 55 98     MOV        qword ptr [RBP + local_70],RDX
        0010162d 48 b8 5f        MOV        RAX,0x7365745f726f665f
                 66 6f 72 
                 5f 74 65 73
        00101637 48 ba 74        MOV        RDX,0x7d293a5f676e6974
                 69 6e 67 
                 5f 3a 29 7d
```

The stack layout is as follows. The flag is stored at `sbox[0x80]`.

```
0x7ffe448519f0: 0x9999999999999999      0x9999999999999999 --- round_key[8], block_out[8]
0x7ffe44851a00: 0x060e0d0c050a030b      0x07040f0908010002 --- sbox[16]
0x7ffe44851a10: 0x00007ffe44851b50      0x00007b4248e62142
0x7ffe44851a20: 0x0000003000000008      0xc49e839dffa49b00
0x7ffe44851a30: 0x00007ffe44851a40      0x0000000000000000
0x7ffe44851a40: 0x00007ffe44851af0      0x0000563edee216af
0x7ffe44851a50: 0x0000000000000007      0x0000563edef6d300
0x7ffe44851a60: 0x0000563edef6d2e0      0x0000563edef6d2c0
0x7ffe44851a70: 0x0000563edef6d2a0      0x0000000100000008
0x7ffe44851a80: 0x667b72616d6c616b      0x67616c665f656b61 --- flag = sbox[0x80]
0x7ffe44851a90: 0x7365745f726f665f      0x7d293a5f676e6974
```

The actual implementation of the encryption part is as follows. There is no argument checking in the set/get functions and it is possible to read/write out of range.

```c
void do_encrypt(uint blocks,long key_array,long shift_array,long plaintext_array,long ciphertext_array)

/*...*/

  for (block = 0; block < blocks; block = block + 1) {
    block_out = *(undefined8 *)(plaintext_array + (ulong)(block << 3));
    for (round = 0; round < 0x10; round = round + 1) {
      for (i0 = 0; i0 < 0x10; i0 = i0 + 1) {
        x = (&randval)[(int)(uint)i0];
        y = shift(*(undefined *)(shift_array + (ulong)(round + block * 0x10)),i0);
        sbox[(int)(uint)x] = y;
      }
      for (i1 = 0; i1 < 0x10; i1 = i1 + 1) {
        val = get_nibble(&block_out,i1);
        set_nibble(round_key,sbox[(int)(uint)i1],val); // oob write
      }
      for (i2 = 0; i2 < 0x10; i2 = i2 + 1) {
        val = get_nibble(key_array + (ulong)(block << 3),i2);
        uVar1 = get_nibble(round_key,i2);
        x = shift(uVar1,val);
        set_nibble(round_key,i2,x & 0xf);
      }
      for (i3 = 0; i3 < 0x10; i3 = i3 + 1) {
        x = get_nibble(round_key,i3);
        set_nibble(&block_out,i3,sbox[(int)(uint)sbox[(int)(uint)x]]); // oob read
      }
    }
    *(undefined8 *)((ulong)(block << 3) + ciphertext_array) = block_out;
  }

/*...*/
```

I thought backwards from what I wanted to do as follows.
- Output one byte of the flag as cipher text
- Make `sbox[sbox[x]]` point to 0x8X
- Make sure that `sbox[0:16]=0x8X` ( = first 16 bytes of sbox should be 0x8X)

Assignment to sbox is in the `i0` loop above, and the value is `shift(shift_array[round], i0)`.

From previous research, we know that if you select `0x80` as the first argument of `shift`, `0x8X` will come out regardless of the value of the second argument, so we set `0x80` to `shift_array`. 

I thought this would work, but I'm still having a little problem. Since the output to `block_out` is used from the next round onward, the `round_key` changes, and as a result, the next output to `block_out` is mixed with unnecessary information, making it impossible to extract the flag.

I thought it would be easy to just set all `shift_arary` to `0x80`, but this poses another problem. `round_key` is an uninitialized variable, and a pointer is placed here. Unless this is cleaned up, the ciphertext output result will also depend on ASLR, and the output will change every time.

Therefore, write to `round_key` in the first round, and from then on, `0x80` will continue to be stored in `sbox`. When `shift_array` is configured as `[0, 0x80, 0x80, 0x80, ...]`, the keys are fixed and only the flags are sorted and output.

The byte string to be put in `round_key` can be adjusted from `plaintext_array`. By keeping the 8 bytes of `plaintext_array` the same value, a specific character will appear. The sorting order only depends on `randval`, so you can specify which character you want to extract.

Also, due to the specifications of `set_nibble`, the nibble calculation is an addition without a mask, so we need to restore the output result.

For example, the output of `}` will be `Block 0: 4d4d4d4d4d4d4d4d`. This is because `set_nibble` calculates `(0x7d*0x10+0x7d) & 0xff`, so this can also be solved by writing the reverse process.

Script is [here](https://github.com/jt00000/ctf.writeup/blob/master/kalmar2024/symmetry/sym2.py)。

`kalmar{u_c4n_r34d!n0w_d0_wR1t1n}`

# Symmetry 3
Now we need to write. Since oob write is in the stack variable, it seems possible to create a ROP. Get the leak from the stack using the same method as `Symmetry 2`.

Of the previous implementation, we use this part as oob write.

```
        val = get_nibble(&block_out,i1);
        set_nibble(round_key,sbox[(int)(uint)i1],val);
```


When the oob read (used in `Symmetry 2`) reads 1 byte from `sbox[x]`, it simultaneously writes 4 bits to `round_key[x//2]`. 

It is important to note that the second argument of `set_nibble` is used by dividing.
When `x` is an even number, write the upper side of the nibble (equivalent to & 0x0f0), and when it is an odd number, write the lower side (equivalent to & 0x0f).

The stack layout is as follows (reposted). This time, we want to target the return address, so we will rewrite it aiming for +0x58 from `round_key`.

```
0x7ffe448519f0: 0x9999999999999999      0x9999999999999999 --- round_key[8], block_out[8]
0x7ffe44851a00: 0x060e0d0c050a030b      0x07040f0908010002 --- sbox[16]
0x7ffe44851a10: 0x00007ffe44851b50      0x00007b4248e62142
0x7ffe44851a20: 0x0000003000000008      0xc49e839dffa49b00
0x7ffe44851a30: 0x00007ffe44851a40      0x0000000000000000
0x7ffe44851a40: 0x00007ffe44851af0      0x0000563edee216af --- return address
0x7ffe44851a50: 0x0000000000000007      0x0000563edef6d300
0x7ffe44851a60: 0x0000563edef6d2e0      0x0000563edef6d2c0
0x7ffe44851a70: 0x0000563edef6d2a0      0x0000000100000008
0x7ffe44851a80: 0x667b72616d6c616b      0x67616c665f656b61
0x7ffe44851a90: 0x7365745f726f665f      0x7d293a5f676e6974
```

If you set `shift_array` to `0xb0`, you can write to the return address. You can write only one round and discard the rest where it has no effect, so `shift_array` is specified as `[[0xb0]+[0]*0xf]`, contrary to `Symmetry2`.

The replacement location will change depending on the key, so input plain text such as `0123456789abcdef` and check the replacement location and adjust.

Since only 8 bytes can be written, you need to connect to code execution with one_gadget or COP. (I think it is possible to write multiple ROPs, but it was not necessary this time.) 

The situation when returning is as follows. There are heap addresses in good locations that can be controlled as is, but this time I found a good one in one_gadget.

```
───────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffce787ce38  →  0xcccccccccccccccc
$rdx   : 0x00006353c4dcd3e0  →  0xcccccccccccccccc
$rsp   : 0x00007ffce787ce88  →  0xdfaddaeeeebeedfb
$rbp   : 0x00007ffce787cf30  →  0x00007ffce787cf90  →  0x0000000000000001
$rsi   : 0xf               
$rdi   : 0x00007ffce787ce38  →  0xcccccccccccccccc
$rip   : 0x00006353c41325d6  →   ret 
$r8    : 0x00006353c4dcd3e0  →  0xcccccccccccccccc
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x00007cc03a3bf3c0  →  0x0002000200020002
$r12   : 0x00007ffce787d0a8  →  0x00007ffce787f2d8  →  "./challenge"
$r13   : 0x00006353c41326c6  →   endbr64 
$r14   : 0x00006353c4134d88  →  0x00006353c41321e0  →   endbr64 
$r15   : 0x00007cc03a577040  →  0x00007cc03a5782e0  →  0x00006353c4131000  →   jg 0x6353c4131047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffce787ce88│+0x0000: 0xdfaddaeeeebeedfb   ← $rsp
0x00007ffce787ce90│+0x0008: 0x0000000000000007
0x00007ffce787ce98│+0x0010: 0x00006353c4dcd3e0  →  0xcccccccccccccccc
0x00007ffce787cea0│+0x0018: 0x00006353c4dcd3c0  →  0xbeefbeefdeaddead
0x00007ffce787cea8│+0x0020: 0x00006353c4dcd3a0  →  0x00000000000000b0
0x00007ffce787ceb0│+0x0028: 0x00006353c4dcd380  →  0x0000000000000000
0x00007ffce787ceb8│+0x0030: 0x00000001c4135020
0x00007ffce787cec0│+0x0038: "kalmar{fake_flag_for_testing_:)}"
─────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x6353c41325cc                  call   0x6353c41320f0 <__stack_chk_fail@plt>
   0x6353c41325d1                  mov    rbx, QWORD PTR [rbp-0x8]
   0x6353c41325d5                  leave  
●→ 0x6353c41325d6                  ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge", stopped 0x6353c41325d6 in ?? (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x6353c41325d6 → ret 
────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```
The one_gadget is I used is this. rdx is the ciphertext that will be output, so you can adjust it with the key.

```
0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

Connect everything up to this point and we're done.

Script is [here](https://github.com/jt00000/ctf.writeup/blob/master/kalmar2024/symmetry/sym3.py)。

I couldn't solve this on time (15 minutes after cometition.) but I enjoyed alot.