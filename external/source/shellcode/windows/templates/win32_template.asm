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
 %define PEOptionalheader_EipRVA PESection.text_RVA(PayloadEntry)
 PEOptionalHeader_Begin
  PEOptionalHeader_Directory Export,0,0
  PEOptionalHeader_Directory Import,Import_Directorys_RVA,Import_Directorys_VS
 PEOptionalHeader_End

 PESectionHeader .text,'.text',PESectionHeader_Flags_EXECUTABLECODE | PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_EXECUTEACCESS | PESectionHeader_Flags_READACCESS| PESectionHeader_Flags_WRITEACCESS
 PESectionHeader .rdata,'.rdata',PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_READACCESS
 PESectionHeader .data,'.data',PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_READACCESS | PESectionHeader_Flags_WRITEACCESS
 PESectionHeader .bss,'.bss', PESectionHeader_Flags_DATA0 | PESectionHeader_Flags_READACCESS | PESectionHeader_Flags_WRITEACCESS
 PESectionHeader .idata,'.idata',PESectionHeader_Flags_DATAFROMFILE | PESectionHeader_Flags_READACCESS
 PESections_Begin
  
  PESection.text_Begin
PayloadEntry:
   incbin "payload.bin"
   call [PESection.idata_VA(Import.KERNEL32.ExitProcess)]
  PESection.text_End

  PESection.rdata_Begin
    db 0x90
  PESection.rdata_End

  PESection.data_Begin
    db 0x90
  PESection.data_End

  PESection.bss_Begin
    resb 0x100
  PESection.bss_End

  PESection.idata_Begin
  
   Import_Directorys_Begin .idata
    Import_Directory KERNEL32
   Import_Directorys_End

   Import_RVAs_Begin KERNEL32
    Import_RVA KERNEL32,ExitProcess
   Import_RVAs_End

   Import_VAs_Begin KERNEL32
    Import_VA KERNEL32,ExitProcess,0BFF8D4CAh
   Import_VAs_End

   Import_Strings_Begin KERNEL32
    Import_String_Function KERNEL32,ExitProcess,"ExitProcess",07Fh
    Import_String_Dll KERNEL32,"KERNEL32.DLL"
   Import_Strings_End
   
  PESection.idata_End

 PESections_End
BIN_End
