##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 295

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows MessageBox x64',
      'Description' => 'Spawn a dialog via MessageBox using a customizable title, text & icon',
      'Author'      => [
        'pasta <jaguinaga[at]infobytesec.com>'
      ],
      'License'     => GPL_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64
    ))

    icon_opts = ['NO', 'ERROR', 'INFORMATION', 'WARNING', 'QUESTION']
    register_options(
      [
        OptString.new('TITLE', [true, "Messagebox Title", "MessageBox"]),
        OptString.new('TEXT', [true, "Messagebox Text", "Hello, from MSF!"]),
        OptEnum.new('ICON', [true, "Icon type", icon_opts[0], icon_opts])
      ]
    )
  end

  def ror(dword, arg, bits = 32)
    mask = (2**arg) - 1
    mask_bits = dword & mask
    return (dword >> arg) | (mask_bits << (bits - arg))
  end

  def rol(dword, arg, bits = 32)
    return ror(dword, bits - arg, bits)
  end

  def hash(msg)
    hash = 0
    msg.each_byte do |c|
      hash = ror(c.ord + hash, 0xd)
    end
    return hash
  end

  def to_unicode(msg)
    return msg.encode("binary").split('').join("\x00") + "\x00\x00"
  end

  def api_hash(libname, function)
    return (hash(to_unicode(libname.upcase)) + hash(function)) & 0xffffffff
  end

  def generate
    style = 0x00
    case datastore['ICON'].upcase.strip
      # default = NO
    when 'ERROR'
      style = 0x10
    when 'QUESTION'
      style = 0x20
    when 'WARNING'
      style = 0x30
    when 'INFORMATION'
      style = 0x40
    end

    if datastore['EXITFUNC'].upcase.strip == 'PROCESS'
      exitfunc_asm = %(
        xor rcx,rcx
        mov r10d, #{api_hash('kernel32.dll', 'ExitProcess')}
        call rbp
      )
    elsif datastore['EXITFUNC'].upcase.strip == 'THREAD'
      exitfunc_asm = %(
        mov ebx, #{api_hash('kernel32.dll', 'ExitThread')}
        mov r10d, #{api_hash('kernel32.dll', 'GetVersion')}
        call rbp
        add rsp,0x28
        cmp al,0x6
        jl use_exitthread   ; is older than Vista or Server 2003 R2?
        cmp bl,0xe0         ; check if GetVersion change the hash stored in EBX
        jne use_exitthread
        mov ebx, #{api_hash('ntdll.dll', 'RtlExitUserThread')}

        use_exitthread:
        push 0
        pop rcx
        mov r10d,ebx
        call rbp
      )
    end
    exitfunc = Metasm::Shellcode.assemble(Metasm::X64.new, exitfunc_asm).encode_string

    payload_asm = %(
      cld
      and rsp,0xfffffffffffffff0
      call start_main
      push r9
      push r8
      push rdx
      push rcx
      push rsi
      xor rdx,rdx
      mov rdx,qword ptr gs:[rdx+0x60]
      mov rdx,qword ptr ds:[rdx+0x18]
      mov rdx,qword ptr ds:[rdx+0x20]
      next_mod:
      mov rsi,qword ptr ds:[rdx+0x50]
      movzx rcx,word ptr ds:[rdx+0x4a]
      xor r9,r9
      loop_modname:
      xor rax,rax
      lodsb
      cmp al,0x61
      jl not_lowercase
      sub al,0x20
      not_lowercase:
      ror r9d,0xd
      add r9d,eax
      loop loop_modname
      push rdx
      push r9
      mov rdx,qword ptr ds:[rdx+0x20]
      mov eax,dword ptr ds:[rdx+0x3c]
      add rax,rdx
      mov eax,dword ptr ds:[rax+0x88]
      test rax,rax
      je get_next_mod1
      add rax,rdx
      push rax
      mov ecx,dword ptr ds:[rax+0x18]
      mov r8d,dword ptr ds:[rax+0x20]
      add r8,rdx
      check_has:
      jrcxz get_next_mod
      dec rcx
      mov esi,dword ptr ds:[r8+rcx*4]
      add rsi,rdx
      xor r9,r9
      loop_funcname:
      xor rax,rax
      lodsb
      ror r9d,0xd
      add r9d,eax
      cmp al,ah
      jne loop_funcname
      add r9,qword ptr ds:[rsp+0x8]
      cmp r9d,r10d
      jne check_has
      pop rax
      mov r8d,dword ptr ds:[rax+0x24]
      add r8,rdx
      mov cx,word ptr ds:[r8+rcx*2]
      mov r8d,dword ptr ds:[rax+0x1c]
      add r8,rdx
      mov eax,dword ptr ds:[r8+rcx*4]
      add rax,rdx
      pop r8
      pop r8
      pop rsi
      pop rcx
      pop rdx
      pop r8
      pop r9
      pop r10
      sub rsp,0x20
      push r10
      jmp rax
      get_next_mod:
      pop rax
      get_next_mod1:
      pop r9
      pop rdx
      mov rdx,qword ptr ds:[rdx]
      jmp next_mod
      start_main:
      pop rbp
      mov r9, #{style}
      lea rdx,qword ptr ds:[rbp + #{exitfunc.length + 0xf3}]
      lea r8,qword ptr ds:[rbp + #{exitfunc.length + datastore['TEXT'].length + 0xf4}]
      xor rcx,rcx
      mov r10d, #{api_hash('user32.dll', 'MessageBoxA')}
      call rbp
    )

    payload_data = Metasm::Shellcode.assemble(Metasm::X64.new, payload_asm).encode_string
    payload_data << exitfunc
    payload_data << datastore['TEXT'] + "\x00"
    payload_data << datastore['TITLE'] + "\x00"

    return payload_data
  end
end
