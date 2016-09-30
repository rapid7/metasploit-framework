;         MACROS POUR L'IMPORTATION DE FONCTIONS DE DLLS WIN32 v0.9a
;         ==========================================================


;WIN32DLL.INC_TABLE_REGISTER = edi = registre qui pointera la table
;WIN32DLL.INC_PUSH => sauvegarde des registres sur la pile
;WIN32DLL.INC_KERNEL32.DLL = WIN32DLL.INC_9X | WIN32DLL.INC_NT
; |WIN32DLL.INC_2000|r contenant l'adresse de base de KERNEL32.DLL
;WIN32DLL.INC_BYTE_BEGIN = 252 = 1er byte du codage dans la table


;GetBase r
; r -> adresse de base à partir de l'adresse originale contenue dans r

;GetChecksum(chaine)
; EAX -> checksum de chaine
;GetVAExportChecksum(base,checksum)
; EAX -> VA de la fonction de checksum à partir de l'Export Table de
;        l'adresse de base de la DLL parcourue | 0

;DllBegin
; Dll kernel32.dll,"kernel32.dll"
;  [DllFunction LoadLibraryA,...]
;  [DllFunction GetProcAddress,...]
;  ...
; Dll dll [,"dll"]
;  DllFunction function [,"function"|d [,d]]
;  ...
; ...
;DllEnd
;<- WIN32.INC_NO_EXTERN_IMPORT,BYTE.INC_NO_00,FUNCTION.INC_CONVENTION

;================================= General ===================================
%ifndef _WIN32DLL.INC
%define _WIN32DLL.INC

%include "win32.inc"

%macro WIN32DLL.INC 0
 %define WIN32DLL.INC_TABLE_REGISTER edi
 %define WIN32DLL.INC_PUSH
 %define WIN32DLL.INC_9X 0BFF70000h
 %define WIN32DLL.INC_NT 077F00000h
 %define WIN32DLL.INC_2000 077E00000h
 %define WIN32DLL.INC_KERNEL32.DLL WIN32DLL.INC_9X
 %define WIN32DLL.INC_BYTE_BEGIN 252
 %define DllChecksum_Define WIN32DLL.INC_BYTE_BEGIN
 %define DllFunction_Define WIN32DLL.INC_BYTE_BEGIN+1
 %define DllDll_Define WIN32DLL.INC_BYTE_BEGIN+2
 %define DllEnd_Define WIN32DLL.INC_BYTE_BEGIN+3
%endmacro

WIN32DLL.INC

;=================================== DLLs ====================================
%macro GetBase 1
 And %1,0FFFF0000h
GetBase_Boucle:
 cmp word[%1],'MZ'
 JX e,GetBase_Fin,+1
 Sub eax,10000h
 Jmp GetBase_Boucle,-1
GetBase_Fin:
%endmacro

%macro Function_GetChecksum 0
Function GetChecksum,GetChecksum_Chaine
FunctionBegin
 pushf
 push esi
 push edx
 cld

 mov esi,[GetChecksum_Chaine]
 Mov edx,0
GetChecksum_BoucleChar:
 Mov eax,0
 lodsb
 shl ax,8                              ;AX=cc00
 add edx,eax                           ;ajoute le caractère au checksum
 Cmp eax,0
 JX z,GetChecksum_Fin,+1               ;si fin de chaîne
 Mov eax,0
 lodsb                                 ;AX=cc
 add edx,eax                           ;ajoute le caractère au checksum
 Cmp al,0
 JX nz,GetChecksum_BoucleChar,-1       ;si pas fin de chaîne
GetChecksum_Fin:
 mov eax,edx
 pop edx
 pop esi
 popf
FunctionEnd
%endmacro

%macro Function_GetVAExportChecksum 0
Function GetVAExportChecksum,GetVAExportChecksum_VA,GetVAExportChecksum_Checksum
FunctionBegin
 pushf
 push edi
 push esi
 push edx
 push ecx
 push ebx
 cld

 mov esi,[GetVAExportChecksum_VA]
 mov ebx,esi
 mov ebx,[byte ebx+03Ch]
 add ebx,esi                           ;EBX=adresse header PE
 mov ebx,[byte ebx+078h]
 add ebx,esi                           ;EBX=adresse Export Table
 mov edx,[byte ebx+018h]               ;EDX=nombre noms
 Mov ecx,0                             ;ECX=indice courant liste adresses noms

GetVAExportChecksum_BoucleNom:
 mov edi,[byte ebx+020h]
 add edi,esi                           ;EDI=adresse liste adresses noms
 mov edi,[edi+4*ecx]
 add edi,esi                           ;EDI=adresse chaîne

 push edx
 mov edx,[GetVAExportChecksum_Checksum] ;EDX=checksum recherché
 xchg esi,edi                          ;ESI=adresse chaîne
GetVAExportChecksum_BoucleChar:
 Mov eax,0
 lodsb
 shl ax,8                              ;AX=cc00
 sub edx,eax                           ;soustrait le caractère du checksum
 Cmp eax,0
 JX z,GetVAExportChecksum_FinNom,+1    ;si fin de chaîne
 Mov eax,0
 lodsb                                 ;AX=cc
 sub edx,eax                           ;soustrait le caractère du checksum
 Cmp al,0
 JX nz,GetVAExportChecksum_BoucleChar,-1 ;si pas fin de chaîne
GetVAExportChecksum_FinNom:
 xchg esi,edi                          ;EDI=adresse chaîne
 test edx,edx
 pop edx
 JX z,GetVAExportChecksum_NomTrouve,+1 ;si checksum recherchée

 inc ecx
 cmp ecx,edx
 JX nae,GetVAExportChecksum_BoucleNom,-1 ;si pas fin => boucle suivant
 Mov eax,0
 Jmp GetVAExportChecksum_Fin,+1        ;sinon fin

GetVAExportChecksum_NomTrouve:
 Mov eax,0
 mov edi,[byte ebx+024h]
 add edi,esi                           ;EDI=adresse liste ordinaux
 mov ax,[edi+2*ecx]                    ;AX=ordinal

 mov edi,[byte ebx+01Ch]
 add edi,esi                           ;EDI=adresse liste adresses
 mov eax,[edi+4*eax]
 add eax,esi                           ;EAX=adresse fonction

GetVAExportChecksum_Fin:
 pop ebx
 pop ecx
 pop edx
 pop esi
 pop edi
 popf
FunctionEnd
%endmacro

%macro DllBegin 0
 %ifctx Dll
  Error WIN32DLL,DllBegin =X=> DllBegin
 %else
  %push Dll
  %undef Dll_LoadLibraryA_Define
  %undef Dll_GetProcAddress_Define
  %undef Dll_kernel32.dll_Define
  %assign Dll_Function_Assign 1
  %define FUNCTION.INC_CONVENTION Std
  %ifdef WIN32.INC_NO_EXTERN_IMPORT
   %ifdef WIN32DLL.INC_PUSH
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,ebp
     push ebp
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,edi
     push edi
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,esi
     push esi
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,edx
     push edx
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,ecx
     push ecx
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,ebx
     push ebx
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,eax
     push eax
    %endif
   %endif
   Call %$End,+1
  %endif
 %endif
%endmacro

%macro Dll 1-2
 %ifctx Dll
  %define Dll_Dll_Define %1
  %ifdef WIN32.INC_NO_EXTERN_IMPORT
   %if %0==2
    %ifnidn %1,kernel32.dll
     %define Dll_kernel32.dll
     db %2,DllDll_Define
    %endif
   %else
    Error WIN32DLL,NO_EXTERN_IMPORT => Dll dll,"dll"
   %endif
  %endif
 %else
  Error WIN32DLL,Dll => DllBegin
 %endif
%endmacro

%macro DllFunctionExternImport 2-3
 %if %0==2
  %ifstr %2
   db %2,DllFunction_Define
  %else
   db DllChecksum_Define
   dd ~(%2)
  %endif
  %1_Equ equ Dll_Function_Assign
  ExternImport %1,Dll_Dll_Define,[byte WIN32DLL.INC_TABLE_REGISTER+%1_Equ]
  %assign Dll_Function_Assign Dll_Function_Assign+4
 %else
  ExternImport %1,Dll_Dll_Define,%3
 %endif
%endmacro

%macro DllFunction 1-3
 %ifctx Dll
  %ifdef WIN32.INC_NO_EXTERN_IMPORT
   %if %0>1
    %ifidn %1,LoadLibraryA
     %if %0==3
      DllFunctionExternImport %1,%2,%3
      %define Dll_LoadLibraryA_Define
     %endif
    %elifidn %1,GetProcAddress
     %if %0==3
      DllFunctionExternImport %1,%2,%3
      %define Dll_GetProcAddress_Define
     %endif
    %else
     %ifndef Dll_LoadLibraryA_Define
      DllFunctionExternImport LoadLibraryA,000023761h ;'oL'+'da'+'iL'+'rb'+'ra'+'Ay'
      %define Dll_LoadLibraryA_Define
     %endif
     %ifndef Dll_GetProcAddress_Define
      DllFunctionExternImport GetProcAddress,00002DBA1h ;'eG'+'Pt'+'or'+'Ac'+'dd'+'er'+'ss'
      %define Dll_GetProcAddress_Define
     %endif
     %if %0==2
      %ifstr %2
       %ifndef Dll_kernel32.dll
        db "kernel32.dll",DllDll_Define
        %define Dll_kernel32.dll
       %endif
      %endif
      DllFunctionExternImport %1,%2
     %else
      DllFunctionExternImport %1,%2,%3
     %endif
    %endif
   %else
    Error WIN32DLL,NO_EXTERN_IMPORT => DllFunction function,"function"|d [,d]
   %endif
  %else
   ExternImport %1,Dll_Dll_Define
  %endif
 %else
  Error WIN32DLL,DllFunction => DllBegin
 %endif
%endmacro

%macro DllEnd 0
 %ifctx Dll
  %ifdef WIN32.INC_NO_EXTERN_IMPORT
   db DllEnd_Define
   Function_GetVAExportChecksum
   %$End:

   %ifnidn WIN32DLL.INC_KERNEL32.DLL,edx
    Mov edx,WIN32DLL.INC_KERNEL32.DLL
   %endif

   pop esi                             ;ESI=offset jump table
   push esi
   mov edi,esi                         ;EDI=offset jump table
   mov ebp,esi
   dec ebp                             ;EBP=offset jump table-1
DllEnd_BoucleNom:
   mov ebx,esi                         ;EBX=dÚbut chaîne courante
DllEnd_BoucleChar:
   lodsb
   cmp al,WIN32DLL.INC_BYTE_BEGIN
   JX b,DllEnd_BoucleChar,-1           ;si <252

   dec esi                             ;sinon >=252 =>chaine ou fin
   Mov ah,0
   mov [esi],ah                        ;00 de fin de chaîne
   inc esi

   cmp al,WIN32DLL.INC_BYTE_BEGIN
   JX e,DllEnd_252,+1                  ;si =252
   cmp al,WIN32DLL.INC_BYTE_BEGIN+2
   JX a,DllEnd_End,+1                  ;si =255

   push edi                            ;sauve EDI
   push esi                            ;sauve ESI
   JX e,DllEnd_254,+1                  ;si =254

DllEnd_253:                            ;sinon =253 => fonction
   push edx                            ;sauve EDX
   xchg WIN32DLL.INC_TABLE_REGISTER,ebp
   GetProcAddress(edx,ebx)
   xchg WIN32DLL.INC_TABLE_REGISTER,ebp
   pop edx
   pop esi
   pop edi
   stosd                               ;ajoute à la jump table
   Jmp DllEnd_BoucleNom,-1

DllEnd_252:                            ;=252 => checksum
   lodsd
   not eax
   TemporaryBegin dword,-,eax
   %define BYTE.INC_TEMPORARY_REGISTER Temporary_Ret
   GetVAExportChecksum(edx,eax)
   %undef BYTE.INC_TEMPORARY_REGISTER
   TemporaryEnd
   stosd                               ;ajoute à la jump table
   Jmp DllEnd_BoucleNom,-1

DllEnd_254:                            ;=254 => dll
   xchg WIN32DLL.INC_TABLE_REGISTER,ebp
   LoadLibraryA(ebx)
   xchg WIN32DLL.INC_TABLE_REGISTER,ebp
   mov edx,eax                         ;EDX=handle de la DLL
   pop esi
   pop edi
   Jmp DllEnd_BoucleNom,-1

DllEnd_End:                            ;=255
   pop WIN32DLL.INC_TABLE_REGISTER
   dec WIN32DLL.INC_TABLE_REGISTER
   %ifdef WIN32DLL.INC_PUSH
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,eax
     pop eax
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,ebx
     pop ebx
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,ecx
     pop ecx
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,edx
     pop edx
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,esi
     pop esi
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,edi
     pop edi
    %endif
    %ifnidni WIN32DLL.INC_TABLE_REGISTER,ebp
     pop ebp
    %endif
   %endif
  %endif
  %pop
 %else
  Error WIN32DLL,DllEnd => DllBegin
 %endif
%endmacro

%endif
