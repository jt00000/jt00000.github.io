---
layout: page
title: "[writeup] GoogleCTF2020 / sprint [EN]"
date: 2020-08-30 00:00:00 -0000
---

#### REV / sprint (65 solves)

I participated in GoogleCTF2020 as PwnaSonic and I solved 2 REV task. (beginner, sprint)

This task `sprint` is very fun one and I really enjoyed playing. So I decide to write this. 

---

#### Binary Analysis
The code is fairly simple like this.

```c
undefined8 main(void)

{
  undefined8 uVar1;
  ushort *local_98;
  ushort *local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50 [2];
  ushort *local_40;
  
  local_40 = (ushort *)mmap((void *)0x4000000,0x4000000,3,0x22,-1,0);
  memcpy(local_40,M,0xf134);
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50[0] = 0;
  local_98 = local_40;
  local_90 = local_40;
  puts("Input password:");
  uVar1 = 0x101270;
  __isoc99_scanf("%255s",local_40 + 0x7000);
  while (local_98 != local_40 + 0x7fff) {
    sprintf((char *)0x6000000,(char *)local_98,&DAT_0011116a,0,&local_98,0x6000000,(ulong)*local_90,
            local_90,&local_90,local_88,&local_88,local_80,&local_80,local_78,&local_78,local_70,
            &local_70,local_68,&local_68,local_60,&local_60,local_58,&local_58,local_50[0],local_50,
            uVar1);
  }
  if (local_40[0x7400] != 0) {
    printf("Flag: %s\n",local_40 + 0x7400);
  }
  return 0;
}
```

- First, some memcopy to mmaped fixed address and receiving 255 char as user input.  
- Then, there are weired `sprintf` loop until condition is met.
- Finaly, check the flag value.

Main issue is in `sprintf`'s args. Let's, check them.  
Break point here.

```
        001013b0 e8 cb fc        CALL       sprintf                                          int sprintf(char * __s, char * _
                 ff ff
```

And this is the output. Lock at `$rsi`.

```
$ gdb ./sprint
gef➤  b*0x0000555555554000+0x13b0
gef➤  r

(snip)

   0x5555555553a3 <main+542>       mov    rsi, rax
   0x5555555553a6 <main+545>       mov    edi, 0x6000000
   0x5555555553ab <main+550>       mov    eax, 0x0
 → 0x5555555553b0 <main+555>       call   0x555555555080 <sprintf@plt>
   ↳  0x555555555080 <sprintf@plt+0>  jmp    QWORD PTR [rip+0x11fba]        # 0x555555567040 <sprintf@got.plt>
      0x555555555086 <sprintf@plt+6>  push   0x5
      0x55555555508b <sprintf@plt+11> jmp    0x555555555020
      0x555555555090 <__cxa_finalize@plt+0> jmp    QWORD PTR [rip+0x11f62]        # 0x555555566ff8
      0x555555555096 <__cxa_finalize@plt+6> xchg   ax, ax
      0x555555555098                  add    BYTE PTR [rax], al
──────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
sprintf@plt (
   $rdi = 0x0000000006000000 → 0x0000000000000000,
   $rsi = 0x0000000004000000 → "%1$00038s%3$hn%1$65498s%1$28672s%9$hn",
   $rdx = 0x000055555556516a → 0x25203a67616c4600
)
──────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sprint", stopped 0x5555555553b0 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555553b0 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ c

(snip)

   0x5555555553a3 <main+542>       mov    rsi, rax
   0x5555555553a6 <main+545>       mov    edi, 0x6000000
   0x5555555553ab <main+550>       mov    eax, 0x0
 → 0x5555555553b0 <main+555>       call   0x555555555080 <sprintf@plt>
   ↳  0x555555555080 <sprintf@plt+0>  jmp    QWORD PTR [rip+0x11fba]        # 0x555555567040 <sprintf@got.plt>
      0x555555555086 <sprintf@plt+6>  push   0x5
      0x55555555508b <sprintf@plt+11> jmp    0x555555555020
      0x555555555090 <__cxa_finalize@plt+0> jmp    QWORD PTR [rip+0x11f62]        # 0x555555566ff8
      0x555555555096 <__cxa_finalize@plt+6> xchg   ax, ax
      0x555555555098                  add    BYTE PTR [rax], al
──────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
sprintf@plt (
   $rdi = 0x0000000006000000 → 0x2020202020202020,
   $rsi = 0x0000000004000026 → "%1$00074s%3$hn%1$65462s%1$*8$s%7$hn",
   $rdx = 0x000055555556516a → 0x25203a67616c4600
)
──────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sprint", stopped 0x5555555553b0 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555553b0 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

There are bunch of format string in memcopyed address(0x4000000 ~ ?).

```
gef➤  x/s $rsi
0x4000026:	"%1$00074s%3$hn%1$65462s%1$*8$s%7$hn"
gef➤  
0x400004a:	"%1$00108s%3$hn%1$65428s%1$1s%6$hn"
gef➤  
0x400006c:	"%1$00149s%3$hn%1$65387s%1$*8$s%1$2s%7$hn"

(snip)

0x40013d9:	"%1$05119s%3$hn%1$60417s%1$59392s%7$hn"
gef➤  
0x40013ff:	"%1$05153s%3$hn%1$60383s%1$0s%6$hn"
gef➤  
0x4001421:	"%1$65534s%3$hn"
gef➤  
```

Now I realized that this is `sprint`'f' challenge and we have to analysis these words.

Another fact is that there are many stack values in this sprintf call.

```
gef➤  tel
0x00007fffffffdc50│+0x0000: 0x0000000000003125 ("%1"?)	 ← $rsp
0x00007fffffffdc58│+0x0008: 0x0000000004000000  →  "%1$00038s%3$hn%1$65498s%1$28672s%9$hn"
0x00007fffffffdc60│+0x0010: 0x00007fffffffdd38  →  0x0000000004000000  →  "%1$00038s%3$hn%1$65498s%1$28672s%9$hn"
0x00007fffffffdc68│+0x0018: 0x0000000000007000
0x00007fffffffdc70│+0x0020: 0x00007fffffffdd40  →  0x0000000000007000
0x00007fffffffdc78│+0x0028: 0x0000000000000000
0x00007fffffffdc80│+0x0030: 0x00007fffffffdd48  →  0x0000000000000000
0x00007fffffffdc88│+0x0038: 0x0000000000000000
0x00007fffffffdc90│+0x0040: 0x00007fffffffdd50  →  0x0000000000000000
0x00007fffffffdc98│+0x0048: 0x0000000000000000
gef➤  
0x00007fffffffdca0│+0x0050: 0x00007fffffffdd58  →  0x0000000000000000
0x00007fffffffdca8│+0x0058: 0x0000000000000000
0x00007fffffffdcb0│+0x0060: 0x00007fffffffdd60  →  0x0000000000000000
0x00007fffffffdcb8│+0x0068: 0x0000000000000000
0x00007fffffffdcc0│+0x0070: 0x00007fffffffdd68  →  0x0000000000000000
0x00007fffffffdcc8│+0x0078: 0x0000000000000000
0x00007fffffffdcd0│+0x0080: 0x00007fffffffdd70  →  0x0000000000000000
0x00007fffffffdcd8│+0x0088: 0x0000000000000000
0x00007fffffffdce0│+0x0090: 0x00007fffffffdd78  →  0x0000000000000000
0x00007fffffffdce8│+0x0098: 0x0000555555555270  →  <main+235> jmp 0x5555555553bc <main+567>
gef➤  tel
```

Stack value have changed while some breaks and continues. I checked these changes carefully and tryed to understand whats going on.

Point #1: Stack values are used as register.
- `%3` is like instruction pointer(IP) and `%4 ~ %23` are registers. 
- Even number is for reference(=for read), Odd number is for dereference(=for write). Except`%4`(as *reg0 write) and `%5`(as *reg0 read and reg0 write).

![stack](/assets/sprint/01.png)

Point #2: There are 2 forms in format strings.  
- form 1 is mov. 

![form1](/assets/sprint/02.png)

- form 2 is jnz.

![form2](/assets/sprint/03.png)

With these knowledge, I disassembled all instructions by hand. (because im stupid :p)

There are 4 parts in this challenge.


`0x4000000 - 0x400034f`: Create array[256] with "not prime -> 1, prime -> 0"

`0x4000374 - 0x4000527`: Check input length is 254.

`0x4000546 - 0x4000e51`: "Solve MAZE"

`0x4000e60 - 0x4001421`: Generate flag.


Let's check from start.

- `0x4000000:  "%1$00038s%3$hn%1$65498s%1$28672s%9$hn"`: Write %9(I named reg1) with 28672 (=0x7000)
- `0x4000026:  "%1$00074s%3$hn%1$65462s%1$*8$s%7$hn"`: Write reg0(%7) with reg1(*8). Since reg0 has 0x4000000 and `$hn` write only short size(0xffff), reg0 value will be `0x4007000`.
- `0x400004a:  "%1$00108s%3$hn%1$65428s%1$1s%6$hn"`: Write *reg0(0x4007000) with 1.
- `0x400006c:  "%1$00149s%3$hn%1$65387s%1$*8$s%1$2s%7$hn"`: Write reg0 with reg1 + 2.

Like this, I dig deeper and write pseudo code for checking what I found.

First part can be easily checked because array is from 0x4007000 to 0x40071f0 when binary finish exec line #0x4000374.

You can check this state with,

- 1: set break point to reg2 == 0x100 (`watch *0x00007fffffffdc78 == 0x100` in my case)
- 2: Run binary and input random value.
- 3: Check address `0x4007000`

```
gef➤  hexdump 0x4007000 200
0x0000000004007000     01 00 01 00 00 00 00 00 01 00 00 00 01 00 00 00    ................
0x0000000004007010     01 00 01 00 01 00 00 00 01 00 00 00 01 00 01 00    ................
0x0000000004007020     01 00 00 00 01 00 00 00 01 00 01 00 01 00 00 00    ................
0x0000000004007030     01 00 01 00 01 00 01 00 01 00 00 00 01 00 00 00    ................
0x0000000004007040     01 00 01 00 01 00 01 00 01 00 00 00 01 00 01 00    ................
0x0000000004007050     01 00 00 00 01 00 00 00 01 00 01 00 01 00 00 00    ................
0x0000000004007060     01 00 01 00 01 00 01 00 01 00 00 00 01 00 01 00    ................
0x0000000004007070     01 00 01 00 01 00 00 00 01 00 00 00 01 00 01 00    ................
0x0000000004007080     01 00 01 00 01 00 00 00 01 00 01 00 01 00 00 00    ................
0x0000000004007090     01 00 00 00 01 00 01 00 01 00 01 00 01 00 00 00    ................
0x00000000040070a0     01 00 01 00 01 00 00 00 01 00 01 00 01 00 01 00    ................
0x00000000040070b0     01 00 00 00 01 00 01 00 01 00 01 00 01 00 01 00    ................
0x00000000040070c0     01 00 00 00 01 00 01 00    ........
gef➤  
0x00000000040070c8     01 00 00 00 01 00 00 00 01 00 01 00 01 00 00 00    ................
0x00000000040070d8     01 00 00 00 01 00 01 00 01 00 00 00 01 00 01 00    ................
0x00000000040070e8     01 00 01 00 01 00 01 00 01 00 01 00 01 00 01 00    ................
0x00000000040070f8     01 00 01 00 01 00 00 00 01 00 01 00 01 00 00 00    ................
0x0000000004007108     01 00 01 00 01 00 01 00 01 00 00 00 01 00 00 00    ................
0x0000000004007118     01 00 01 00 01 00 01 00 01 00 01 00 01 00 01 00    ................
0x0000000004007128     01 00 00 00 01 00 00 00 01 00 01 00 01 00 01 00    ................
0x0000000004007138     01 00 00 00 01 00 01 00 01 00 01 00 01 00 00 00    ................
0x0000000004007148     01 00 01 00 01 00 00 00 01 00 01 00 01 00 01 00    ................
0x0000000004007158     01 00 00 00 01 00 01 00 01 00 01 00 01 00 00 00    ................
0x0000000004007168     01 00 00 00 01 00 01 00 01 00 01 00 01 00 01 00    ................
0x0000000004007178     01 00 01 00 01 00 00 00 01 00 00 00 01 00 01 00    ................
0x0000000004007188     01 00 00 00 01 00 00 00    ........
gef➤  
0x0000000004007190     01 00 01 00 01 00 01 00 01 00 01 00 01 00 01 00    ................
0x00000000040071a0     01 00 01 00 01 00 00 00 01 00 01 00 01 00 01 00    ................
0x00000000040071b0     01 00 01 00 01 00 01 00 01 00 01 00 01 00 00 00    ................
0x00000000040071c0     01 00 01 00 01 00 00 00 01 00 00 00 01 00 01 00    ................
0x00000000040071d0     01 00 00 00 01 00 01 00 01 00 01 00 01 00 00 00    ................
0x00000000040071e0     01 00 00 00 01 00 01 00 01 00 01 00 01 00 01 00    ................
0x00000000040071f0     01 00 01 00 01 00 00 00 01 00 01 00 01 00 01 00    ................
```

break at `0x555555554000 + 0x13b0`( call sprintf ) is also useful in this analysis.

Second part is check input length is 254 or not. 

Third part is the main and most interesting one.  

- First, build MAP with this code.

```
# ARRAY: 256 sized array with array[i] is (0: i is prime, 1: i is not prime) (located at 0x4007000)
# RANDOM: given 256 random bytes. (located at 0x400f000)

# build map
MAP = []
for i in range 256:
    MAP.append(ARRAY[STREAM[i]])
```
Result is below. Now you can see the MAP.

```
[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
[1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
[1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1]
[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0]
[1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1]
[1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0]
[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]
[1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1]
[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0]
[1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0]
[1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0]
[1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1]
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]
[1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1]
[1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0]
```

Our initial position is 0x11. (described at 0x400f100)  

- Second, parse user input to determine next position. User input must be either `u`, `d`, `l`, `r`(up, down, left, right).

- There are 2 check in last of this third part, `0x4000d97` and `0x4000dfa`.
    - `0x4000d97` check reg4. reg4 is used as "collision flag" in this part. This flag must be true and if there is invalid input, or user position is where `MAP[position] = 1`(user on the wall.) or out of map, the flag would be false.
    - `0x4000dfa` check reg2. reg2 is used as "goal numbers" value. There is check bytes at `0x400f103 ~ 0x400f10c: "83 01 af 49 ad c1 0f 8b e1"` and each number of "0x100-x" indicates position on the map. For example, first goal is 0x100-0x83=0x7d -> (0x7, 0xd) is first goal.We have to correct 9 goals with 254 inputs of `udlr`.

Finally I wrote map and check route. Correct input is `ddrrrrrrddrrrrrrrrddllrruullllllllddddllllllddddrrrrrrrruurrddrrddrrlluulluullddlllllllluuuurrrrrruuuuuulllllldduurrrrrrddddddllllllddddrrrrrruuddlllllluuuuuurruuddllddrrrrrruuuurrrrrruurrllddllllllddddllllllddddrrddllrruulluuuurrrrrruullrruurruuuurrrrrr` and you will get flag.

![map](/assets/sprint/04.png)

Here is map script.

```python
# Part1: generate prime array
array = [0]*256

array[0] = 1
array[1] = 1

delta = 2
while(delta < 256): 
    # print delta, array[delta]
    if array[delta] == 0:
        for i in range(delta*2, 256, delta):
            array[i] = 1
    else:
        pass
    delta += 1
    
# for i in range(16):
    # print array[i*16:i*16+16]

# Part2: check input length ( snip )

# Part3: solve maze

# build map 
stream = "cc b0 e7 7b bc c0 ee 3a fc 73 81 d0 7a 69 84 e2 48 e3 d7 59 11 6b f1 b3 86 0b 89 c5 bf 53 65 65 f0 ef 6a bf 08 78 c4 2c 99 35 3c 6c dc e0 c8 99 c8 3b ef 29 97 0b b3 8b cc 9d fc 05 1b 67 b5 ad 15 c1 08 d0 45 45 26 43 45 6d f4 ef bb 49 06 ca 73 6b bc e9 50 97 05 e5 97 d3 b5 47 2b ad 25 8b ae af 41 e5 d8 14 f4 83 e6 f0 c0 98 0a ac a1 95 f5 b5 d3 53 f0 97 ef 9d d4 3b 3b 0b e7 17 07 1f 6c f1 1e 44 92 b2 57 07 b7 36 8f 53 c9 ea 10 90 62 df 1d 07 b3 71 53 61 1a 2b 78 bf c1 b5 c6 3b ea 2b 44 17 a0 84 ca 8f b7 3b 38 2f e8 73 84 ad 44 ef f8 ad 8c 1f ea 7f cd c5 b3 49 05 03 95 a7 44 b5 91 69 f8 95 6c e5 87 53 4e 47 92 be 80 d0 80 1d ad f1 3d e3 df 35 61 f1 e7 0d 71 c5 02 4f 20 5e a2 8b c4 61 32 0f a8 be 7e 29 d1 6d 2a d9 55 47 07 83 ea 2b 79 95 4f 3d a3 11 dd c1 1d 89".split(' ') # this from 0x400f000

MAP = []

for i in range(256):
    MAP.append(array[int(stream[i], 16)])

print "map"
for i in range(16):
    print MAP[i*16:i*16+16]

target = [125, 255, 81, 183, 83, 63, 241, 117, 31] # this from 0x400f102 with subtract from 0x100 each value.
for i in range(16):
    p = ''
    for j in range(16):
        if MAP[i*16+j] == 1:
            p += 'o '
        else:
            if i*16+j in target:
                p += str(target.index(i*16+j))+' '
            elif i*16+j == 0x11:
                p += 's '
                
            else:
                p += '  '
    # print MAP[i*16:i*16+16]
    print p
```

#### Generate Flag part
This part is additional and you don't have to understand. This is just for my fun.

There are 39 bytes `0x400f10d ~ 0x400f134: "9e ff a1 26 14 3b 68 60 6b c7 34 c4 0a 1b 6d 8c c9 47 76 65 32 74 5f e2 25 72 32 74 62 0a b9 81 6e c6 17 e3 c5 66 7d"` and first 39 * 4 inputs and some calc. Code is here.

```python
s = "9e ff a1 26 14 3b 68 60 6b c7 34 c4 0a 1b 6d 8c c9 47 76 65 32 74 5f e2 25 72 32 74 62 0a b9 81 6e c6 17 e3 c5 66 7d".split(' ')
inp = "ddrrrrrrddrrrrrrrrddllrruullllllllddddllllllddddrrrrrrrruurrddrrddrrlluulluullddlllllllluuuurrrrrruuuuuulllllldduurrrrrrddddddllllllddddrrrrrruuddlllllluuuuuurruuddllddrrrrrruuuurrrrrruurrllddllllllddddllllllddddrrddllrruulluuuurrrrrruullrruurruuuurrrrrr"

assert(len(s) == 39)
ans = ""
for i in range(len(s)):
    r3 = 0
    for j in inp[i*4:i*4+4]:
        r3 *= 4
        if j == "u":
            r3 += 0 
        elif j == "r":
            r3 += 1 
        elif j == "d":
            r3 += 2 
        else:
            r3 += 3 

    ans += chr((r3 + int(s[i], 16) & 0xff))

print ans
```
