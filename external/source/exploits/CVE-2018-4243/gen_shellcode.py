from subprocess import check_output

loader_offset = int(check_output('nm -g payload/payload.dylib | grep "T _load"',
        shell=True).split()[0], 16)
inp = open('shellcode.in.s').read()
outp = inp.replace('OFFSET_LOAD', hex(loader_offset))
with open('shellcode.s', 'w') as f:
    f.write(outp)
