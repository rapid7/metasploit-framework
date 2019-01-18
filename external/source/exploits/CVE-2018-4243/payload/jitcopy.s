.global _jitcopy

/* performJITMemcpy inlined into LinkBuffer::linkCode:

JavaScriptCore:__text:0000000187BD18C8                 MOV             X19, #0xC10C
...
JavaScriptCore:__text:0000000187BD1918                 MOV             X0, X8
JavaScriptCore:__text:0000000187BD191C                 MOV             X1, X21
JavaScriptCore:__text:0000000187BD1920                 BL              _memcpy
...
JavaScriptCore:__text:0000000187BD1968                 LDR             X0, [SP,#0x18]
JavaScriptCore:__text:0000000187BD196C                 CBZ             X0, loc_187BD1984
...
JavaScriptCore:__text:0000000187BD1984                 LDUR            X8, [X29,#-0x58]
JavaScriptCore:__text:0000000187BD1988                 ADRP            X9, #___stack_chk_guard@PAGE
JavaScriptCore:__text:0000000187BD198C                 LDR             X9, [X9,#___stack_chk_guard@PAGEOFF]
JavaScriptCore:__text:0000000187BD1990                 LDR             X9, [X9]
JavaScriptCore:__text:0000000187BD1994                 CMP             X9, X8
JavaScriptCore:__text:0000000187BD1998                 B.NE            loc_187BD19E4
JavaScriptCore:__text:0000000187BD199C                 LDP             X29, X30, [SP,#0x100]
JavaScriptCore:__text:0000000187BD19A0                 LDP             X20, X19, [SP,#0xF0]
JavaScriptCore:__text:0000000187BD19A4                 LDP             X22, X21, [SP,#0xE0]
JavaScriptCore:__text:0000000187BD19A8                 LDP             X24, X23, [SP,#0xD0]
JavaScriptCore:__text:0000000187BD19AC                 LDP             X26, X25, [SP,#0xC0]
JavaScriptCore:__text:0000000187BD19B0                 LDP             X28, X27, [SP,#0xB0]
JavaScriptCore:__text:0000000187BD19B4                 ADD             SP, SP, #0x110
JavaScriptCore:__text:0000000187BD19B8                 RET
*/

/* x0 = gadget
 * x1 = stack_check_guard
 * x2 = dst
 * x3 = src
 * x4 = size
 */
_jitcopy:
    sub sp, sp, 0x110

    mov x8, 0
    str x8, [sp,0x18]

    stp x29, x30, [sp,0x100]
    stp x20, x19, [sp,0xf0]
    stp x22, x21, [sp,0xe0]
    stp x24, x23, [sp,0xd0]
    stp x26, x25, [sp,0xc0]
    stp x28, x27, [sp,0xb0]

    add x29, x1, 0x58

    mov x8, x2
    mov x21, x3
    mov x2, x4
    br x0
