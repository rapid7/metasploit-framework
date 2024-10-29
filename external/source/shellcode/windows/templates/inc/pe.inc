;corriger ;???
;raison inconnue ; ?


;gestion message d'erreur structures (%error)
; %define et %ifdef pour tester l'existence de header n‚cessaires
; (pour ‚viter les erreurs de label ind‚finis)

;.edata,.rsrc (icones)

;supprimer macro Directories ? (calcul automatique ?)


;                   MACROS AND DEFINITIONS FOR PE FILES v1.0a
;                   =========================================
;By rix-shogun-agressor (erix@mail.dotcom.fr,rix@dreamnet.org)

;conventions:
;xxx_VA: adresse virtuelle (adresse en m‚moire)
;xxx_RVA: d‚placement d'adresse virtuel (offset d'adresse en m‚moire%baseVA)
;xxx_VS: taille virtuelle (taille en m‚moire)
;xxx_FS: taille fichier
;xxx_FA: adresse fichier (offset dans le fichier)
;xxx_Fa: file alignement
;xxx-Va: virtual alignement (alignement m‚moire)
;xxx_Assign: assignation pour un calcul ‚valu‚ plus tard
;xxx_Define: definition pour un calcul ‚valu‚ plus tard dont une des valeurs
; est toujours inconnue
;xxx_Ifctx: macros pour regrouper plusieurs %ifctx
;xxx: valeur

;sections: text,
;macros de d‚finitions des header: NOM[SousNom]_Begin NOM[SousNom]_End
;                         ou bien: NOM[SousNom]
;define de d‚finitions des headers: NOM[SousNom]_Xxx
;definition de constantes des header: NOM[SousNom]_XXX
;nom interne aux macros NOMHeader NOM[SousNom]_Begin_FA NOM[SousNom]_End_FA

;MacroXXX:macros internes

;xxxx:normal
;xxxxa:align‚ (V=>align‚ virtuel,F=>align‚ fichier)

;equ: valeur calcul‚e d'aprŠs nombres suivants l'endroit de stockage
;%define: d‚claration des constantes utilisables par l'utilisateur
;%assign: d‚claration des variables internes pour les calculs d'equ (_Assign)

;================================= BIN Begin =================================
%ifndef PE.INC
%define PE.INC
%push PE.INC

%include "language.inc"

%macro BIN_Begin 0
 SECTION .text
 BIN_Begin_FA:
 %push BIN_Begin
%endmacro

;================================= MZ Header =================================
%define MZHeader_MinimumMemory 0 ;en paragraphes, … ajouter en fin de m‚moire
%define MZHeader_MaximumMemory 0FFFFh ;en paragraphes, … ajouter en fin de m‚moire
%define MZHeader_Ss 0000h
%define MZHeader_Sp 00B8h ; ?
%define MZHeader_Ip 0000h
%define MZHeader_Cs 0000h

%macro MZHeader 0
 %ifctx BIN_Begin
  BITS 16
  MZHeader_Begin_FA:
  MZHeader_Signature_FA: db 'MZ'
  MZHeader_LastPageBytes_FA: dw (BIN_End_FAa-BIN_Begin_FA) % 512
  MZHeader_PagesNumber_FA: dw (BIN_End_FAa-BIN_Begin_FA)/512+1
  MZHeader_RelocationsNumber_FA: dw 0
  MZHeader_HeaderParagraphsNumber_FA: dw (MZExtendedHeader_End_FA-MZHeader_Begin_FA)/16
  MZHeader_MinimumMemory_FA: dw MZHeader_MinimumMemory
  MZHeader_MaximumMemory_FA: dw MZHeader_MaximumMemory
  MZHeader_Ss_FA: dw MZHeader_Ss
  MZHeader_Sp_FA: dw MZHeader_Sp
  MZHeader_Checksum_FA: dw 0
  MZHeader_Ip_FA: dw MZHeader_Ip
  MZHeader_Cs_FA: dw MZHeader_Cs
  MZHeader_RelocationTableFA_FA: dw 0040h                         ;0040h=>fichier PE
  MZHeader_OverlayNumber_FA: dw 0
  MZHeader_End_FA:
  %repl MZHeader
 %else
  %error PE.INC error: MZHeader => BIN_Begin
 %endif
%endmacro

;============================ MZ Extended Header =============================
%macro MZExtendedHeader 0
 %ifctx MZHeader
  MZExtendedHeader_Begin_FA:
  dd 0
  dw 0
  %rep 26
   db 0
  %endrep
  MZExtendedHeader_PEHeaderFA_FA: dd PEHeader_Begin_FA
  MZExtendedHeader_End_FA:
  %repl MZExtendedHeader
 %else
  %error PE.INC error: MZExtendedHeader => MZHeader
 %endif
%endmacro

;================================== MZ Text ==================================
%macro MZSection.text_Begin 0
 %ifctx MZExtendedHeader
  MZSection.text_Begin_FA:
  %define MZSection.text_VA(a) (a)-MZSection.text_Begin_FA
  %repl MZSection.text_Begin
 %else
  %error PE.INC error: MZSection.text_Begin => MZExtendedHeader
 %endif
%endmacro

%macro MZSection.text_End 0
 %ifctx MZSection.text_Begin
  MZSection.text_End_FA:
  DbAlign MZSection.text_Begin_FA,16
  MZSection.text_End_FAa:
  %repl MZSection.text_End
 %else
  %error PE.INC error: MZSection.text_End => MZSection.text_Begin
 %endif
%endmacro

;================================= PE Header =================================
 %define PEHeader_Machine_386 14Ch
 %define PEHeader_Machine_486 14Dh
 %define PEHeader_Machine_PENTIUM 14Eh
%define PEHeader_Machine PEHeader_Machine_386
%define PEHeader_DateHour 0
%define PEHeader_OptionalHeaderFS 0E0h ; ?
 %define PEHeader_Characteristics_NORELOCATIONS 0000000000000001b
 %define PEHeader_Characteristics_EXECUTABLEIMAGE 0000000000000010b ;ex‚cutable/librairie
 %define PEHeader_Characteristics_16B 0000000001000000b ;programme 16 bits
 %define PEHeader_Characteristics_BYTESREVERSEDLOW 0000000010000000b
 %define PEHeader_Characteristics_32B 0000000100000000b ;programme 32 bits
 %define PEHeader_Characteristics_NODEBUGINFORMATIONS 0000001000000000b
 %define PEHeader_Characteristics_SYSTEMFILE 0001000000000000b
 %define PEHeader_Characteristics_DLL 0010000000000000b
 %define PEHeader_Characteristics_BYTESREVERSEDHIGH 1000000000000000b
%define PEHeader_Characteristics PEHeader_Characteristics_NORELOCATIONS | PEHeader_Characteristics_EXECUTABLEIMAGE | PEHeader_Characteristics_32B

%macro PEHeader 0
 %ifctx MZSection.text_End
  BITS 32
  PEHeader_Begin_FA:
  PEHeader_Signature_FA: db 'PE',00h,00h
  PEHeader_Machine_FA: dw PEHeader_Machine
  PEHeader_SectionsNumber_FA: dw PEHeader_SectionsNumber
  %assign PEHeader_SectionsNumber_Assign 0
  PEHeader_DateHour_FA: dd PEHeader_DateHour
  dd 0
  dd 0
  PEHeader_OptionalHeaderFS_FA: dw PEHeader_OptionalHeaderFS
  PEHeader_Characteristics_FA: dw PEHeader_Characteristics
  PEHeader_End_FA:
  %define PESection_RVA(a) PESectionCur_RVAa_Assign+(a)-PESectionCur_FAa_Define
  %define PESection.text_RVA(a) PESection.text_RVAa+(a)-PESection.text_Begin_FAa
  %define PESection.rdata_RVA(a) PESection.rdata_RVAa+(a)-PESection.rdata_Begin_FAa
  %define PESection.data_RVA(a) PESection.data_RVAa+(a)-PESection.data_Begin_FAa
  %define PESection.bss_RVA(a) PESection.bss_RVAa+(a)-PESection.bss_Begin_FAa
  %define PESection.idata_RVA(a) PESection.idata_RVAa+(a)-PESection.idata_Begin_FAa
  %repl PEHeader
 %else
  %error PE.INC error: PEHeader => MZSection.text_End
 %endif
%endmacro

;============================ PE Optional Header =============================
%define PEOptionalHeader_MajorLinkerVersion 0
%define PEOptionalHeader_MinorLinkerVersion 0
%define PEOptionalheader_EipRVA PESection.text_RVA(PESection.text_Begin_FAa)
%define PEOptionalHeader_ImageVAa 00400000h
%define PEOptionalHeader_Va 1000h
%define PEOptionalHeader_Fa 200h
%define PEOptionalHeader_MajorOSVersion 4
%define PEOptionalHeader_MinorOSVersion 0
%define PEOptionalHeader_MajorProgramVersion 0
%define PEOptionalHeader_MinorProgramVersion 0
%define PEOptionalHeader_MajorSubSystemVersion 4
%define PEOptionalHeader_MinorSubSystemVersion 0
 %define PEOptionalHeader_SubSystem_DRIVER 1
 %define PEOptionalHeader_SubSystem_GUI 2
 %define PEOptionalHeader_SubSystem_CONSOLE 3
 %define PEOptionalHeader_SubSystem_POSIX 7 
%define PEOptionalHeader_SubSystem PEOptionalHeader_SubSystem_GUI
 %define PEOptionalHeader_DllFlags_NOTIFYPROCESSATTACHMENTS 0001b
 %define PEOptionalHeader_DllFlags_NOTIFYPROCESSDETACHMENTS 0010b
 %define PEOptionalHeader_DllFlags_NOTIFYTHREADSATTACHMENTS 0100b
 %define PEOptionalHeader_DllFlags_NOTIFYTHREADSDETACHMENTS 1000b
%define PEOptionalHeader_DllFlags 0
%define PEOptionalHeader_ReservedStackVSa 0
%define PEOptionalHeader_CommittedStackVSa 0
%define PEOptionalHeader_ReservedHeapVSa 0
%define PEOptionalHeader_CommittedHeapVSa 0

%macro PEOptionalHeader_Begin 0
 %ifctx PEHeader
  PEOptionalHeader_Begin_FA:
  PEOptionalHeader_Signature_FA: db 0Bh,01h
  PEOptionalHeader_MajorLinkerVersion_FA: db PEOptionalHeader_MajorLinkerVersion
  PEOptionalHeader_MinorLinkerVersion_FA: db PEOptionalHeader_MinorLinkerVersion
  PEOptionalHeader_CodeFSa_FA: dd PESection.text_FSa
  PEOptionalHeader_InitializedDataFSa_FA: dd PEOptionalHeader_InitializedDataFSa
  %assign PEOptionalHeader_InitializedDataFSa_Assign 0
  PEOptionalHeader_UninitializedDataVSa_FA: dd PESection.bss_VSa
  PEOptionalHeader_EipRVA_FA: dd PEOptionalheader_EipRVA
  PEOptionalHeader_CodeRVAa_FA: dd PESection.text_RVAa
  %assign PEOptionalHeader_DataRVAa_Assign 0
  PEOptionalHeader_DataRVAa_FA: dd PEOptionalHeader_DataRVAa ; ?
  PEOptionalHeader_ImageVAa_FA: dd PEOptionalHeader_ImageVAa
  PEOptionalHeader_Va_FA: dd PEOptionalHeader_Va
  PEOptionalHeader_Fa_FA: dd PEOptionalHeader_Fa
  PEOptionalHeader_MajorOSVersion_FA: dw PEOptionalHeader_MajorOSVersion
  PEOptionalHeader_MinorOSVersion_FA: dw PEOptionalHeader_MinorOSVersion
  PEOptionalHeader_MajorProgramVersion_FA: dw PEOptionalHeader_MajorProgramVersion
  PEOptionalHeader_MinorProgramVersion_FA: dw PEOptionalHeader_MinorProgramVersion
  PEOptionalHeader_MajorSubSystemVersion_FA: dw PEOptionalHeader_MajorSubSystemVersion
  PEOptionalHeader_MinorSubSystemVersion_FA: dw PEOptionalHeader_MinorSubSystemVersion
  dd 0
  PEOptionalHeader_ImageVSa_FA: dd PEOptionalHeader_ImageVSa
  PEOptionalHeader_HeadersFSa_FA: dd PESections_Begin_FAa-BIN_Begin_FA
  PEOptionalHeader_Checksum_FA: dd 0
  PEOptionalHeader_SubSystem_FA: dw PEOptionalHeader_SubSystem
  PEOptionalHeader_DllFlags_FA: dw PEOptionalHeader_DllFlags
  PEOptionalHeader_ReservedStackVSa_FA: dd PEOptionalHeader_ReservedStackVSa ;???
  PEOptionalHeader_CommittedStackVSa_FA: dd PEOptionalHeader_CommittedStackVSa ;???
  PEOptionalHeader_ReservedHeapVSa_FA: dd PEOptionalHeader_ReservedHeapVSa ;???
  PEOptionalHeader_CommittedHeapVSa_FA: dd PEOptionalHeader_CommittedHeapVSa ;???
  dd 0
  PEOptionalHeader_DirectoriesNumber_FA: dd PEOptionalHeader_DirectoriesNumber
  %assign PEOptionalHeader_DirectoriesNumber_Assign 0
  %repl PEOptionalHeader_Begin
 %else
  %error PE.INC error: PEOptionalHeader_Begin => PEHeader
 %endif
%endmacro

;PEOptionalHeader_Directory name,RVA,FS
%macro PEOptionalHeader_Directory 3
 %ifctx PEOptionalHeader_Begin
  PEOptionalHeader%1RVA_FA: dd %2
  PEOptionalHeader%1FS_FA: dd %3
  %assign PEOptionalHeader_DirectoriesNumber_Assign PEOptionalHeader_DirectoriesNumber_Assign+1
 %else
  %error PE.INC error: PEOptionalHeader_Directory => PEOptionalHeader_Begin
 %endif
%endmacro

%macro PEOptionalHeader_End 0
 %ifctx PEOptionalHeader_Begin
  PEOptionalHeader_End_FA:
  DbAlign PEOptionalHeader_Begin_FA,PEHeader_OptionalHeaderFS
  PEOptionalHeader_End_FAa:
  PEOptionalHeader_DirectoriesNumber equ PEOptionalHeader_DirectoriesNumber_Assign
  %repl PEOptionalHeader_End
 %else
  %error PE.INC error: PEOptionalHeader_End => PEOptionalHeader_Begin
 %endif
%endmacro

;============================= PE Section Header =============================
 %define PESectionHeader_Flags_EXECUTABLECODE 00000000000000000000000000100000b
 %define PESectionHeader_Flags_DATAFROMFILE 00000000000000000000000001000000b
 %define PESectionHeader_Flags_DATA0 00000000000000000000000010000000b
 %define PESectionHeader_Flags_COMMENTS 00000000000000000000001000000000b
 %define PESectionHeader_Flags_COMMONBLOCKDATA 00000000000000000001000000000000b
 %define PESectionHeader_Flags_FARDATA 00000000000000001000000000000000b
 %define PESectionHeader_Flags_PURGEABLEDATA 00000000000000100000000000000000b
 %define PESectionHeader_Flags_NONMOVABLEDATA 00000000000001000000000000000000b
 %define PESectionHeader_Flags_SHAREDINSTANCES 00010000000000000000000000000000b ;.text
 %define PESectionHeader_Flags_EXECUTEACCESS 00100000000000000000000000000000b
 %define PESectionHeader_Flags_READACCESS 01000000000000000000000000000000b
 %define PESectionHeader_Flags_WRITEACCESS 10000000000000000000000000000000b

;PESectionHeader .name,'.name',flags
%macro PESectionHeader 3
 %ifctx PEOptionalHeader_End
  PESectionHeader%1_Name_FA: db %2
  DbAlign PESectionHeader%1_Name_FA,8
  PESectionHeader%1_VS_FA: dd PESection%1_VS
  PESectionHeader%1_RVAa_FA: dd PESection%1_RVAa
  PESectionHeader%1_FSa_FA: dd PESection%1_FSa
  PESectionHeader%1_FAa_FA: dd PESectionHeader%1_FAa
  dd 0
  dd 0
  dw 0
  dw 0
  PESectionHeader%1_Flags_FA: dd %3
 %else
  %error PE.INC error: PESectionHeader => PEOptionalHeader_End
 %endif
%endmacro

;================================ PE Sections ================================
%macro PESections_Begin 0
 %ifctx PEOptionalHeader_End
  PESections_Begin_FA:
  DbAlign BIN_Begin_FA,PEOptionalHeader_Fa
  PESections_Begin_FAa:
  %assign PESectionPrec_FSa_Assign PESections_Begin_FAa-BIN_Begin_FA
  %assign PESectionPrec_RVAa_Assign 0
  %assign PESectionCur_RVAa_Assign 0
  %define PESectionCur_FAa_Define 0
   ;impossible dans MacroPESection_Begin
   %define PESection_VA(a) PEOptionalHeader_ImageVAa+PESectionCur_RVAa_Assign+(a)-PESectionCur_FAa_Define
   %define PESection.text_VA(a) PEOptionalHeader_ImageVAa+PESection.text_RVAa+(a)-PESection.text_Begin_FAa
   %define PESection.rdata_VA(a) PEOptionalHeader_ImageVAa+PESection.rdata_RVAa+(a)-PESection.rdata_Begin_FAa
   %define PESection.data_VA(a) PEOptionalHeader_ImageVAa+PESection.data_RVAa+(a)-PESection.data_Begin_FAa
   %define PESection.bss_VA(a) PEOptionalHeader_ImageVAa+PESection.bss_RVAa+(a)-PESection.bss_Begin_FAa
   %define PESection.idata_VA(a) PEOptionalHeader_ImageVAa+PESection.idata_RVAa+(a)-PESection.idata_Begin_FAa
   %repl PESections_Begin
 %else
  %error PE.INC error: PESections_Begin => PEOptionalHeader
 %endif
%endmacro

;MacroPESection_End .name
%macro MacroPESection_End 1
 PESection%1_End_FA:
 DbAlign BIN_Begin_FA,PEOptionalHeader_Fa
 PESection%1_End_FAa:
 %assign PEHeader_SectionsNumber_Assign PEHeader_SectionsNumber_Assign+1
 PESection%1_VS equ PESection%1_End_FA-PESection%1_Begin_FAa
%endmacro


%macro PESection.text_Begin 0
 %ifctx PESections_Begin
  %assign PESectionCur_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign-1)/PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  PESection.text_Begin_FAa:
  %define PESectionCur_FAa_Define PESection.text_Begin_FAa
  %push PESection.text_Begin
 %else
  %error PE.INC error: PESection.text_Begin => PESections_Begin
 %endif
%endmacro

%macro PESection.text_End 0
 %ifctx PESection.text_Begin
  MacroPESection_End .text
  %assign PESectionPrec_RVAa_Assign PESectionCur_RVAa_Assign 
  PESection.text_RVAa equ PESectionPrec_RVAa_Assign
  PESection.text_FSa equ PESection.text_End_FAa-PESection.text_Begin_FAa
  %assign PESectionPrec_FSa_Assign PESection.text_FSa
  PESectionHeader.text_FAa equ PESection.text_Begin_FAa
  %pop
 %else
  %error PE.INC error: PESection.text_End => PESection.text_Begin
 %endif
%endmacro


%macro PESection.rdata_Begin 0
 %ifctx PESections_Begin
  %assign PESectionCur_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign-1)/PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  PESection.rdata_Begin_FAa:
  %define PESectionCur_FAa_Define PESection.rdata_Begin_FAa
  %push PESection.rdata_Begin
 %else
  %error PE.INC error: PESection.rdata_Begin => PESections_Begin
 %endif
%endmacro

%macro PESection.rdata_End 0
 %ifctx PESection.rdata_Begin
  MacroPESection_End .rdata
  %assign PESectionPrec_RVAa_Assign PESectionCur_RVAa_Assign
  PESection.rdata_RVAa equ PESectionPrec_RVAa_Assign
  PESection.rdata_FSa equ PESection.rdata_End_FAa-PESection.rdata_Begin_FAa
  %assign PESectionPrec_FSa_Assign PESection.rdata_FSa
  PESectionHeader.rdata_FAa equ PESection.rdata_Begin_FAa
  %assign PEOptionalHeader_InitializedDataFSa_Assign PEOptionalHeader_InitializedDataFSa_Assign+PESection.rdata_FSa
  %if PEOptionalHeader_DataRVAa_Assign == 0
   %assign PEOptionalHeader_DataRVAa_Assign PESection.rdata_RVAa
  %endif
  %pop
 %else
  %error PE.INC error: PESection.rdata_End => PESection.rdata_Begin
 %endif
%endmacro


%macro PESection.data_Begin 0
 %ifctx PESections_Begin
  %assign PESectionCur_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign-1)/PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  PESection.data_Begin_FAa:
  %define PESectionCur_FAa_Define PESection.data_Begin_FAa
  %push PESection.data_Begin
 %else
  %error PE.INC error: PESection.data_Begin => PESections_Begin
 %endif
%endmacro

%macro PESection.data_End 0
 %ifctx PESection.data_Begin
  MacroPESection_End .data
  %assign PESectionPrec_RVAa_Assign PESectionCur_RVAa_Assign
  PESection.data_RVAa equ PESectionPrec_RVAa_Assign
  PESection.data_FSa equ PESection.data_End_FAa-PESection.data_Begin_FAa
  PESectionHeader.data_FAa equ PESection.data_Begin_FAa
  %assign PESectionPrec_FSa_Assign PESection.data_FSa
  %assign PEOptionalHeader_InitializedDataFSa_Assign PEOptionalHeader_InitializedDataFSa_Assign+PESection.data_FSa
  %if PEOptionalHeader_DataRVAa_Assign == 0
   %assign PEOptionalHeader_DataRVAa_Assign PESection.data_RVAa
  %endif
  %pop
 %else
  %error PE.INC error: PESection.data_End => PESection.data_Begin
 %endif
%endmacro


%macro PESection.bss_Begin 0
 %ifctx PESections_Begin
  %assign PESectionCur_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign-1)/PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  SECTION .bss
  PESection.bss_Begin_FAa:
  %define PESectionCur_FAa_Define PESection.bss_Begin_FAa
  %push PESection.bss_Begin
 %else
  %error PE.INC error: PESection.bss_Begin => PESections_Begin
 %endif
%endmacro

%macro PESection.bss_End 0
 %ifctx PESection.bss_Begin
  PESection.bss_End_FA:
  ResbAlign PESection.bss_Begin_FAa,PEOptionalHeader_Va
  PESection.bss_End_FAa:
  %assign PEHeader_SectionsNumber_Assign PEHeader_SectionsNumber_Assign+1
  PESection.bss_VS equ PESection.bss_End_FA-PESection.bss_Begin_FAa
  PESection.bss_VSa equ PESection.bss_End_FAa-PESection.bss_Begin_FAa
  SECTION .text
  %assign PESectionPrec_RVAa_Assign PESectionCur_RVAa_Assign
  PESection.bss_RVAa equ PESectionPrec_RVAa_Assign
  PESection.bss_FSa equ 0
  %assign PESectionPrec_FSa_Assign PESection.bss_VSa
  PESectionHeader.bss_FAa equ 0
  %pop
 %else
  %error PE.INC error: PESection.bss_End => PESection.bss_Begin
 %endif
%endmacro


%macro PESection.idata_Begin 0
 %ifctx PESections_Begin
  %assign PESectionCur_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign-1)/PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  PESection.idata_Begin_FAa:
  %define PESectionCur_FAa_Define PESection.idata_Begin_FAa
  %push PESection.idata_Begin
 %else
  %error PE.INC error: PESection.idata_Begin => PESections_Begin
 %endif
%endmacro

%macro PESection.idata_End 0
 %ifctx PESection.idata_Begin
  MacroPESection_End .idata
  %assign PESectionPrec_RVAa_Assign PESectionCur_RVAa_Assign
  PESection.idata_RVAa equ PESectionPrec_RVAa_Assign
  PESection.idata_FSa equ PESection.idata_End_FAa-PESection.idata_Begin_FAa
  PESectionHeader.idata_FAa equ PESection.idata_Begin_FAa
  %assign PESectionPrec_FSa_Assign PESection.idata_FSa
  %pop
 %else
  %error PE.INC error: PESection.idata_End => PESection.idata_Begin
 %endif
%endmacro


%macro PESection.rsrc_Begin 0
 %ifctx PESections_Begin
  %assign PESectionCur_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign-1)/PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  PESection.rsrc_Begin_FAa:
  %define PESectionCur_FAa_Define PESection.rsrc_Begin_FAa
  %push PESection.rsrc_Begin
 %else
  %error PE.INC error: PESection.rsrc_Begin => PESections_Begin
 %endif
%endmacro

%macro PESection.rsrc_End 0
 %ifctx PESection.rsrc_Begin
  MacroPESection_End .rsrc
  %assign PESectionPrec_RVAa_Assign PESectionCur_RVAa_Assign
  PESection.rsrc_RVAa equ PESectionPrec_RVAa_Assign
  PESection.rsrc_FSa equ PESection.rsrc_End_FAa-PESection.rsrc_Begin_FAa
  PESectionHeader.rsrc_FAa equ PESection.rsrc_Begin_FAa
  %assign PESectionPrec_FSa_Assign PESection.rsrc_FSa
  %pop
 %else
  %error PE.INC error: PESection.rsrc_End => PESection.rsrc_Begin
 %endif
%endmacro


%macro PESections_End 0
 %ifctx PESections_Begin
  PESections_End_FAa:
  PEHeader_SectionsNumber equ PEHeader_SectionsNumber_Assign
  PEOptionalHeader_InitializedDataFSa equ PEOptionalHeader_InitializedDataFSa_Assign
  PEOptionalHeader_DataRVAa equ PEOptionalHeader_DataRVAa_Assign
  %assign PESectionPrec_RVAa_Assign (((PESectionPrec_RVAa_Assign+PESectionPrec_FSa_Assign) / PEOptionalHeader_Va)+1)*PEOptionalHeader_Va
  PEOptionalHeader_ImageVSa equ PESectionPrec_RVAa_Assign
  Import_Directorys_RVA equ Import_Directorys_Assign
  %repl PESections_End
 %else
  %error PE.INC error: PESections_End => PESections_Begin
 %endif
%endmacro

;============================= Import Directorys =============================
;Import_Directorys_Begin sectionname
%macro Import_Directorys_Begin 1
 Import_Directorys_Begin_FA:
 %assign Import_Directorys_Assign PESectionCur_RVAa_Assign+Import_Directorys_Begin_FA-PESectionCur_FAa_Define
 %push Import_Directorys_Begin
%endmacro

;Import_Directory dlllogicalname
%macro Import_Directory 1
 %ifctx Import_Directorys_Begin
  dd PESection_RVA(Import.%1_RVAs)
  dd 0 ;??? (date … 0)
  dd 0FFFFFFFFh
  dd PESection_RVA(Import.%1_String_Dll)
  dd PESection_RVA(Import.%1_VAs)
 %else
  %error PE.INC error: Import_Directory => Import_Directorys_Begin
 %endif
%endmacro

%macro Import_Directorys_End 0
 %ifctx Import_Directorys_Begin
  times 5 dd 0
  Import_Directorys_End_FA:
  Import_Directorys_VS equ Import_Directorys_End_FA-Import_Directorys_Begin_FA
  %pop
 %else
  %error PE.INC error: Import_Directorys_End => Import_Directorys_Begin
 %endif
%endmacro


;Import_RVAs_Begin dlllogicalname
%macro Import_RVAs_Begin 1
 Import.%1_RVAs:
 %push Import_RVAs_Begin
%endmacro

;Import_RVA dlllogicalname,functionlogicalname
%macro Import_RVA 2
 %ifctx Import_RVAs_Begin
  dd PESection_RVA(Import.%1.%2_String_Function)
 %else
  %error PE.INC error: Import_RVA => Import_RVAs_Begin
 %endif
%endmacro

%macro Import_RVAs_End 0
 %ifctx Import_RVAs_Begin
  dd 0
  %pop
 %else
  %error PE.INC error: Import_RVAs_End => Import_RVAs_Begin
 %endif
%endmacro


;Import_VAs_Begin dlllogicalname
%macro Import_VAs_Begin 1
 Import.%1_VAs:
 %push Import_VAs_Begin
%endmacro

;Import_VA dlllogicalname,functionlogicalname,[va]
%macro Import_VA 2-3 0FFFFFFFFh
 %ifctx Import_VAs_Begin
  Import.%1.%2: dd %3
  %2 equ PEOptionalHeader_ImageVAa+PESectionCur_RVAa_Assign+Import.%1.%2-PESectionCur_FAa_Define
 %else
  %error PE.INC error: Import_VA => Import_VAs_Begin
 %endif
%endmacro

%macro Import_VAs_End 0
 %ifctx Import_VAs_Begin
  dd 0
  %pop
 %else
  %error PE.INC error: Import_VAs_End => Import_VAs_Begin
 %endif
%endmacro


;Import_Strings_Begin dlllogicalname
%macro Import_Strings_Begin 1
 Import.%1_Strings:
 %push Import_Strings_Begin
%endmacro

;Import_String_Function dlllogicalname,functionlogicalname,"name",[ordinal]
%macro Import_String_Function 3-4 0h
 %ifctx Import_Strings_Begin
  Import.%1.%2_String_Function:
  dw %4
  db %3,0
 %else
  %error PE.INC error: Import_String_Function => Import_Strings_Begin
 %endif
%endmacro

;Import_String_Dll dlllogicalname,"dllname"
%macro Import_String_Dll 2
 %ifctx Import_Strings_Begin
  Import.%1_String_Dll:
  db %2,0
  %repl Import_String_Dll
 %else
  %error PE.INC error: Import_String_Dll => Import_Strings_Begin
 %endif
%endmacro

%macro Import_Strings_End 0
 %ifctx Import_String_Dll
  %pop
 %else
  %error PE.INC error: Import_Strings_End => Import_String_Dll
 %endif
%endmacro

;================================== BIN End ==================================
%macro BIN_End 0
 %ifctx PESections_End
  BIN_End_FA:
  DbAlign BIN_Begin_FA,PEOptionalHeader_Fa
  BIN_End_FAa:
  %pop
 %else
  %error PE.INC error: BIN_End => PESections_End
 %endif 
%endmacro

%endif
