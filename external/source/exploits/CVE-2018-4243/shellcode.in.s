start:
b go

dlsym:
.word 0x1337
.word 0x1337

go:
ldr x1, dlsym

adr x8, start
ldr x7, =(0x1000+OFFSET_LOAD)
add x0, x8, x7

ldr x7, =0x1000000
add x2, x8, x7

blr x0
