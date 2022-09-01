#ifndef _BPF_DEFS_H_
#define _BPF_DEFS_H_


/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)            \
    ((struct bpf_insn) {                    \
        .code  = CODE,                    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = IMM })

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_DW | BPF_IMM,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = (__u32) (IMM) }),            \
    ((struct bpf_insn) {                    \
        .code  = 0, /* zero is reserved opcode */    \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = ((__u64) (IMM)) >> 32 })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* Program exit */

#define BPF_EXIT_INSN()                        \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_EXIT,            \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = 0 })


/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)                    \
    BPF_LD_IMM64_RAW(DST, 0, IMM)

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)                \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

// varies from userspace bpf_map_info definition so need to redefine
struct bpf_map_info_kernel
{
    __u32 type;
    __u32 id;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    char  name[BPF_OBJ_NAME_LEN];
    __u32 ifindex;
    __u32 btf_vmlinux_value_type_id;
    __u64 netns_dev;
    __u64 netns_ino;
    __u32 btf_id;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
} __attribute__((aligned(8)));


int create_map(union bpf_attr* map_attrs);
int update_map_element(int map_fd, uint64_t key, void* value, uint64_t flags);
int lookup_map_element(int map_fd, int64_t key, void* pDestBuff);
int obj_get_info_by_fd(union bpf_attr* attrs);
int run_bpf_prog(struct bpf_insn* insn, uint32_t cnt, int* prog_fd_out);

#endif