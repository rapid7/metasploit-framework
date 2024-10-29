;                             PE FILE STRUCTURE
;                             =================

%include "pe.inc"

BIN_Begin
 MZHeader
 MZExtendedHeader
 MZSection.text_Begin
  push cs
  pop ds
  mov dx,MZSection.text_VA(text_string)
  mov ah,09
  int 21h
  mov ax,4C01h
  int 21h
  text_string: db 'This program cannot be run in DOS mode.',0Dh,0Ah,'$'
 MZSection.text_End

 PEHeader
 %define PEOptionalheader_EipRVA PESection.text_RVA(mondebut)
 PEOptionalHeader_Begin
  PEOptionalHeader_Directory Export,0,0
  PEOptionalHeader_Directory Import,Import_Directorys_RVA,Import_Directorys_VS
;  PEOptionalHeader_Directory Resource,0,0
;  PEOptionalHeader_Directory Exception,0,0
;  PEOptionalHeader_Directory Security,0,0
;  PEOptionalHeader_Directory Relocations,0,0
;  PEOptionalHeader_Directory Debug,0,0
;  PEOptionalHeader_Directory ImageDescription,0,0
;  PEOptionalHeader_Directory MachineSpecific,0,0
;  PEOptionalHeader_Directory ThreadLocalStorage,0,0
 PEOptionalHeader_End

 PESectionHeader .text,'.text',PESectionHeader_Flags_EXECUTABLECODE | PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_EXECUTEACCESS | PESectionHeader_Flags_READACCESS
 PESectionHeader .rdata,'.rdata',PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_READACCESS
 PESectionHeader .data,'.data',PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_READACCESS | PESectionHeader_Flags_WRITEACCESS
 PESectionHeader .bss,'.bss', PESectionHeader_Flags_DATA0 | PESectionHeader_Flags_READACCESS | PESectionHeader_Flags_WRITEACCESS
 PESectionHeader .idata,'.idata',PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_READACCESS
 PESections_Begin
  PESection.text_Begin
  int 03h
mondebut:
MB_OK equ 0
   mov eax,MB_OK
   push eax
   mov eax,PESection.rdata_VA(message)
   call [GetCommandLineA]
   push eax
   push eax
   mov eax,0
   push eax
   call [MessageBoxA]
   call [PESection.idata_VA(Import.KERNEL32.ExitProcess)]
   mov [PESection.text_VA(text1)],eax
   mov [PESection.rdata_VA(rdata1)],ebx
   mov [PESection.data_VA(data1)],ecx
   mov [PESection.bss_VA(bss1)],edx
text1:
   jmp short mondebut
  PESection.text_End

  PESection.rdata_Begin
message: db "coucou",0
rdata1: times 1001h db 22h ;db 'data1'
  PESection.rdata_End

  PESection.data_Begin
data1: times 1205h db 0FEh
  PESection.data_End

  PESection.bss_Begin
bss1: resb 1001h
  PESection.bss_End

  PESection.idata_Begin
   Import_Directorys_Begin .idata
    Import_Directory KERNEL32
    Import_Directory USER32
   Import_Directorys_End

   Import_RVAs_Begin KERNEL32
    Import_RVA KERNEL32,GetCommandLineA
    Import_RVA KERNEL32,ExitProcess
   Import_RVAs_End
   Import_RVAs_Begin USER32
    Import_RVA USER32,MessageBoxA
   Import_RVAs_End

   Import_VAs_Begin KERNEL32
    Import_VA KERNEL32,GetCommandLineA,0BFF8C5ACh
    Import_VA KERNEL32,ExitProcess,0BFF8D4CAh
   Import_VAs_End
   Import_VAs_Begin USER32
    Import_VA USER32,MessageBoxA
   Import_VAs_End

   Import_Strings_Begin KERNEL32
    Import_String_Function KERNEL32,GetCommandLineA,"GetCommandLineA",0D0h
    Import_String_Function KERNEL32,ExitProcess,"ExitProcess",07Fh
    Import_String_Dll KERNEL32,"KERNEL32.DLL"
   Import_Strings_End
   Import_Strings_Begin USER32
    Import_String_Function USER32,MessageBoxA,"MessageBoxA"
    Import_String_Dll USER32,"USER32.DLL"
   Import_Strings_End
  PESection.idata_End



 PESections_End
BIN_End
