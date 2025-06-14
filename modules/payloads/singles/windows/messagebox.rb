##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 231

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::BlockApi

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows MessageBox',
        'Description' => 'Spawns a dialog via MessageBox using a customizable title, text & icon',
        'Author' => [
          'corelanc0d3r <peter.ve[at]corelan.be>', # original payload module
          'jduck' # some ruby factoring
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86
      )
    )

    # Register MessageBox options
    register_options(
      [
        OptString.new('TITLE', [ true, 'Messagebox Title (max 255 chars)', 'MessageBox' ], max_length: 255),
        OptString.new('TEXT', [ true, 'Messagebox Text (max 255 chars)', 'Hello, from MSF!' ], max_length: 255),
        OptString.new('ICON', [ true, 'Icon type can be NO, ERROR, INFORMATION, WARNING or QUESTION', 'NO' ])
      ]
    )
  end

  #
  # Construct the payload
  #
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

    exitfunc_asm = %(
        push 0
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
        call ebp
      )
    if datastore['EXITFUNC'].upcase.strip == 'THREAD'
      exitfunc_asm = %(
        mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitThread')}
        push #{Rex::Text.block_api_hash('kernel32.dll', 'GetVersion')}
        call ebp
        add esp,0x28
        cmp al,0x6
        jl use_exitthread   ; is older than Vista or Server 2003 R2?
        cmp bl,0xe0         ; check if GetVersion change the hash stored in EBX
        jne use_exitthread
        mov ebx, #{Rex::Text.block_api_hash('ntdll.dll', 'RtlExitUserThread')}
      use_exitthread:
        push 0
        push ebx
        call ebp
      )
    end

    payload_data = %(
      cld
      call start
      #{asm_block_api}
    start:
      pop ebp
      call get_user32
      db "user32.dll", 0x00
    get_user32:
      push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
      call ebp
      push #{style}
      call get_title
      db "#{datastore['TITLE']}", 0x00
    get_title:
      call get_text
      db "#{datastore['TEXT']}", 0x00
    get_text:
      push 0
      push #{Rex::Text.block_api_hash('user32.dll', 'MessageBoxA')}
      call ebp
      #{exitfunc_asm}
    )
    self.assembly = payload_data
    super
  end
end
