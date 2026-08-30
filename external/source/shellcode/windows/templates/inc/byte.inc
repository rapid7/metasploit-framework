;                        MACROS FOR BYTE CODING v0.9a
;                        ============================


;POUR EVITER DES 00 OU DES ERREURS:
;utiliser les macros si nécessaire (pas si tt opérandes sont des registres)
;vérifier Mov [*+offset=0],*
;vérifier Jmp/Call offset multiple de 256,+1
;le byte code d'une macro peut varier
;le byte code d'une fonction ne varie pas
;bytes critiques:00h,0Ah,0Dh,' '
;instructions critiques:adc,and(=' '),enter,esc,imul,ret,sbb,test,or(=0Ah|0Dh)
;éviter [byte r+offset>080h]


;BYTE.INC_NO_00 => ne pas utiliser de bytes 00
;BYTE.INC_FILL_BYTE = 00 = byte de remplissage
;BYTE.INC_FILL_OFFSET = 00 = nombre bytes à rajouter dans les sauts critiques
;BYTE.INC_TEMPORARY_REGISTER = eax|ebx|ecx|edx|NULL (=>push eax|push edx)
;BYTE.INC_LONG_JUMP => sauts longs par défaut
;BYTE.INC_JUMP_DIRECTION = -1 = direction par défaut


;Alias nom_alias,adresse
; -> transforme un Jmp/Call alias en jmp/call adresse

;NotBit0(d)
; -> inverse du bit 0 du dword d
;BitIsNot0(d,n)
; -> 1 si bit n(0..31) du dword d <> 0
;ByteIsNot00(b)
; -> 1 si byte b <> 00
;Word(d,n)
; -> word n(0..1) du dword d
;Byte(d,n)
; -> byte n(0..3) du dword d
;DWordContainNo00(d)
; -> 1 si dword d ne contient pas de bytes 00
;WordContainNo00(w)
; -> 1 si word w ne contient pas de bytes 00
;DWordByteIsNot00(d,n)
; -> 1 si byte n(0..3) du dword d <> 00
;DWordByteIs00(d,n)
; -> 1 si byte n(0..3) du dword d = 00

;TemporaryBegin dword|word|byte [,+|-,r demandé/r refusé|push]
; <- BYTE.INC_TEMPORARY_REGISTER
; -> Temporary_Ret = registre temporaire alloué
;    [esp+Temporary_esp] = ancien [esp]
; ...
;TemporaryEnd

;FillByte
; <- BYTE.INC_NO_00,BYTE.INC_FILL_BYTE
; -> FillByte_Ret = byte de remplissage
;DbAlign adresse_de_départ,valeur_d'alignement [,byte_de_remplissage]
; <- FillByte
;ResbAlign adresse_de_départ,valeur_d'alignement

;Mov r,d|w|b|"string"
;MovD [r],d
;MovW [r],w
;MovB [r],b
;<- BYTE.INC_NO_00,BYTE.INC_TEMPORARY_REGISTER,BYTE.INC_FILL_OFFSET

;Jmp l|d|Alias [,-1|+1]
; <- BYTE.INC_LONG_JUMP
;JX condition_asm,l [,-1|+1]
; <- BYTE.INC_LONG_JUMP
;JnX condition_asm,l [,-1|+1]
; <- BYTE.INC_LONG_JUMP
;Call l|d|Alias [,-1|+1]
;<- BYTE.INC_NO_00,BYTE.INC_TEMPORARY_REGISTER,BYTE.INC_JUMP_DIRECTION,
;   BYTE.INC_FILL_OFFSET,Mov

;Push r|d|"string"
; <- BYTE.INC_NO_00,BYTE.INC_FILL_OFFSET,FillByte,Mov

;Add r,d
;And r,d
;Cmp r,d
;Or r,d
;Sub r,d
;Xor r,d
;<- Mov

;================================= General ===================================
%ifndef _BYTE.INC
%define _BYTE.INC

%include "nasm.inc"

%macro BYTE.INC 0
 %undef BYTE.INC_NO_00
 %define BYTE.INC_FILL_BYTE 0
 %define BYTE.INC_FILL_OFFSET 0
 %undef BYTE.INC_TEMPORARY_REGISTER
 %undef BYTE.INC_LONG_JUMP
 %define BYTE.INC_JUMP_DIRECTION -1
%endmacro

%macro BYTE.INC~ 0
 %define BYTE.INC_FILL_OFFSET 0
 %undef BYTE.INC_TEMPORARY_REGISTER
 %undef BYTE.INC_LONG_JUMP
 %define BYTE.INC_JUMP_DIRECTION -1
%endmacro

BYTE.INC

%macro Alias 2
 %define Alias_%1 %2
%endmacro

;================================== Logic ====================================
%define NotBit0(d) ((~d)&01b)
%define BitIsNot0(d,n) ((d>>n)&01b)
%define ByteIsNot00(b) (BitIsNot0(b,7)|BitIsNot0(b,6)|BitIsNot0(b,5)|BitIsNot0(b,4)|BitIsNot0(b,3)|BitIsNot0(b,2)|BitIsNot0(b,1)|BitIsNot0(b,0))
%define Word(d,n) ((d>>(n*16))&0FFFFh)
%define Byte(d,n) ((d>>(n*8))&0FFh)
%define DWordContainNo00(d) (ByteIsNot00(Byte(d,3))&ByteIsNot00(Byte(d,2))&ByteIsNot00(Byte(d,1))&ByteIsNot00(Byte(d,0)))
%define WordContainNo00(w) (ByteIsNot00(Byte(w,1))&ByteIsNot00(Byte(w,0)))
%define DWordByteIsNot00(d,n) (ByteIsNot00(Byte(d,n)))
%define DWordByteIs00(d,n) (NotBit0(DWordByteIsNot00(d,n)))

;================================ Internal ===================================
;Operand r [,dword|word|byte]
; -> Operand_Size = dword|word|byte
;    Operand_Container = registre dword contenant %1
;    Operand_Unknown si %1 <> r ou %2
%macro Operand 1-2
 %if %0==1
  %ifidni %1,eax
   %define Operand_Size dword
   %define Operand_Container eax
   %undef Operand_Unknown
  %elifidni %1,ebx
   %define Operand_Size dword
   %define Operand_Container ebx
   %undef Operand_Unknown
  %elifidni %1,ecx
   %define Operand_Size dword
   %define Operand_Container ecx
   %undef Operand_Unknown
  %elifidni %1,edx
   %define Operand_Size dword
   %define Operand_Container edx
   %undef Operand_Unknown
  %elifidni %1,esi
   %define Operand_Size dword
   %define Operand_Container esi
   %undef Operand_Unknown
  %elifidni %1,edi
   %define Operand_Size dword
   %define Operand_Container edi
   %undef Operand_Unknown
  %elifidni %1,esp
   %define Operand_Size dword
   %define Operand_Container esp
   %undef Operand_Unknown
  %elifidni %1,ebp
   %define Operand_Size dword
   %define Operand_Container ebp
   %undef Operand_Unknown
  %elifidni %1,ax
   %define Operand_Size word
   %define Operand_Container eax
   %undef Operand_Unknown
  %elifidni %1,bx
   %define Operand_Size word
   %define Operand_Container ebx
   %undef Operand_Unknown
  %elifidni %1,cx
   %define Operand_Size word
   %define Operand_Container ecx
   %undef Operand_Unknown
  %elifidni %1,dx
   %define Operand_Size word
   %define Operand_Container edx
   %undef Operand_Unknown
  %elifidni %1,si
   %define Operand_Size word
   %define Operand_Container esi
   %undef Operand_Unknown
  %elifidni %1,di
   %define Operand_Size word
   %define Operand_Container edi
   %undef Operand_Unknown
  %elifidni %1,sp
   %define Operand_Size word
   %define Operand_Container esp
   %undef Operand_Unknown
  %elifidni %1,bp
   %define Operand_Size word
   %define Operand_Container ebp
   %undef Operand_Unknown
  %elifidni %1,ah
   %define Operand_Size byte
   %define Operand_Container eax
   %undef Operand_Unknown
  %elifidni %1,al
   %define Operand_Size byte
   %define Operand_Container eax
   %undef Operand_Unknown
  %elifidni %1,bh
   %define Operand_Size byte
   %define Operand_Container ebx
   %undef Operand_Unknown
  %elifidni %1,bl
   %define Operand_Size byte
   %define Operand_Container ebx
   %undef Operand_Unknown
  %elifidni %1,ch
   %define Operand_Size byte
   %define Operand_Container ecx
   %undef Operand_Unknown
  %elifidni %1,cl
   %define Operand_Size byte
   %define Operand_Container ecx
   %undef Operand_Unknown
  %elifidni %1,dh
   %define Operand_Size byte
   %define Operand_Container edx
   %undef Operand_Unknown
  %elifidni %1,dl
   %define Operand_Size byte
   %define Operand_Container edx
   %undef Operand_Unknown
  %else
   %undef Operand_Size
   %undef Operand_Container
   %define Operand_Unknown
  %endif
 %else
  %define Operand_Size %2
  %undef Operand_Container
  %define Operand_Unknown
 %endif
%endmacro

;Contained r,dword|word|byte
; -> Contained_Ret = sous-registre de taille %2 du registre %1
;    Contained_L = sous-registre L du registre %1 (?l)
;    Contained_H = sous-registre H du registre %1 (?h)
;    Contained_W = sous-registre word du registre %1 (?x)
;    Contained_D = sous-registre dword du registre %1 (e?x)
%macro Contained 2
 %ifidni %1,eax
  %define Contained_D eax
  %define Contained_W ax
  %define Contained_H ah
  %define Contained_L al
 %elifidni %1,ebx
  %define Contained_D ebx
  %define Contained_W bx
  %define Contained_H bh
  %define Contained_L bl
 %elifidni %1,ecx
  %define Contained_D ecx
  %define Contained_W cx
  %define Contained_H ch
  %define Contained_L cl
 %elifidni %1,edx
  %define Contained_D edx
  %define Contained_W dx
  %define Contained_H dh
  %define Contained_L dl
 %elifidni %1,esi
  %define Contained_D esi
  %define Contained_W si
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,edi
  %define Contained_D edi
  %define Contained_W di
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,esp
  %define Contained_D esp
  %define Contained_W sp
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,ebp
  %define Contained_D ebp
  %define Contained_W bp
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,ax
  %undef Contained_D
  %define Contained_W ax
  %define Contained_H ah
  %define Contained_L al
 %elifidni %1,bx
  %undef Contained_D
  %define Contained_W bx
  %define Contained_H bh
  %define Contained_L bl
 %elifidni %1,cx
  %undef Contained_D
  %define Contained_W cx
  %define Contained_H ch
  %define Contained_L cl
 %elifidni %1,dx
  %undef Contained_D
  %define Contained_W dx
  %define Contained_H dh
  %define Contained_L dl
 %elifidni %1,si
  %undef Contained_D
  %define Contained_W si
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,di
  %undef Contained_D
  %define Contained_W di
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,sp
  %undef Contained_D
  %define Contained_W sp
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,bp
  %undef Contained_D
  %define Contained_W bp
  %undef Contained_H
  %undef Contained_L
 %elifidni %1,ah
  %undef Contained_D
  %undef Contained_W
  %define Contained_H ah
  %undef Contained_L
 %elifidni %1,al
  %undef Contained_D
  %undef Contained_W
  %undef Contained_H
  %define Contained_L al
 %elifidni %1,bh
  %undef Contained_D
  %undef Contained_W
  %define Contained_H bh
  %undef Contained_L
 %elifidni %1,bl
  %undef Contained_D
  %undef Contained_W
  %undef Contained_H
  %define Contained_L bl
 %elifidni %1,ch
  %undef Contained_D
  %undef Contained_W
  %define Contained_H ch
  %undef Contained_L
 %elifidni %1,cl
  %undef Contained_D
  %undef Contained_W
  %undef Contained_H
  %define Contained_L cl
 %elifidni %1,dh
  %undef Contained_D
  %undef Contained_W
  %define Contained_H dh
  %undef Contained_L
 %elifidni %1,dl
  %undef Contained_D
  %undef Contained_W
  %undef Contained_H
  %define Contained_L dl
 %else
  %undef Contained_D
  %undef Contained_W
  %undef Contained_H
  %undef Contained_L
 %endif
 %ifidni %2,dword
  %ifdef Contained_D
   %define Contained_Ret Contained_D
  %else
   %undef Contained_Ret
  %endif
 %elifidni %2,word
  %ifdef Contained_W
   %define Contained_Ret Contained_W
  %else
   %undef Contained_Ret
  %endif
 %elifidni %2,byte
  %ifdef Contained_L
   %define Contained_Ret Contained_L
  %elifdef Contained_H
   %define Contained_Ret Contained_H
  %else
   %undef Contained_Ret
  %endif
 %else
  %undef Contained_Ret
 %endif
%endmacro

;============================ Temporary registers ============================
;TemporaryRequest r,dword|word|byte
; exige le r de taille %2
%macro TemporaryRequest 2
 %ifidni %2,BYTE.INC_TEMPORARY_REGISTER
  Contained BYTE.INC_TEMPORARY_REGISTER,%1
  %undef Temporary_PushPop_Define
  %define Temporary_esp 0
 %else
  push %2
  Contained %2,%1
  %define Temporary_PushPop_Define %2
  %define Temporary_esp 4
 %endif
%endmacro

%macro TemporaryBegin 1-3
 %if %0==1
  %ifdef BYTE.INC_TEMPORARY_REGISTER
   TemporaryRequest %1,BYTE.INC_TEMPORARY_REGISTER
  %else
   TemporaryRequest %1,eax
  %endif
 %else
  %ifidni %2,+ ;r demandé
   TemporaryRequest %1,%3
  %else ;r|push refusé
   %ifdef BYTE.INC_TEMPORARY_REGISTER
    Operand %3
    %ifidni %3,push
     Contained BYTE.INC_TEMPORARY_REGISTER,%1
     %undef Temporary_PushPop_Define
     %define Temporary_esp 0     
    %elifidni Operand_Container,BYTE.INC_TEMPORARY_REGISTER
     %ifidni Operand_Container,eax
      TemporaryRequest %1,edx
     %else
      TemporaryRequest %1,eax
     %endif
    %else
     TemporaryRequest %1,BYTE.INC_TEMPORARY_REGISTER
    %endif
   %else
    %ifidni %3,push
     Contained edx,%1
     %undef Temporary_PushPop_Define
     %define Temporary_esp 0
     Warning BYTE,no BYTE.INC_TEMPORARY_REGISTER => edx
    %else
     Operand %3
     %ifidni Operand_Container,eax
      TemporaryRequest %1,edx
     %else
      TemporaryRequest %1,eax
     %endif
    %endif
   %endif
  %endif
 %endif
 %define Temporary_Ret Contained_Ret
%endmacro

%macro TemporaryEnd 0
 %ifdef Temporary_PushPop_Define
  pop Temporary_PushPop_Define
  %undef Temporary_PushPop_Define
 %endif
%endmacro

;=================================== Db ======================================
%macro FillByte 0
 %ifndef BYTE.INC_NO_00
  %define FillByte_Ret BYTE.INC_FILL_BYTE
 %elif BYTE.INC_FILL_BYTE!=0
  %define FillByte_Ret BYTE.INC_FILL_BYTE
 %else
  %define FillByte_Ret 090h ;nop
 %endif
%endmacro

%macro DbAlign 2-3
 %if ($-%1) % %2 !=0
  FillByte
  %rep %2-(($-%1) % %2)
   %if %0==3
    db %3
   %else
    db FillByte_Ret
   %endif
  %endrep
 %endif
%endmacro

%macro ResbAlign 2
 %if ($-%1) % %2 !=0
  %rep %2-(($-%1) % %2)
   resb 1
  %endrep
 %endif
%endmacro

;=================================== Mov =====================================
%macro MovD_r_NumId_Recursive 2
 %if DWordContainNo00(%2)
  mov %1,%2
 %elif %2==0
  xor %1,%1
 %elif DWordContainNo00(~%2)
  mov %1,~%2
  not %1
 %elif DWordContainNo00(-%2)
  mov %1,-%2
  neg %1
 %else
  Contained %1,dword
  %if DWordByteIs00(%2,3)&DWordByteIs00(%2,2)&DWordByteIs00(%2,1)&DWordByteIsNot00(%2,0) ; 0001
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_L,Byte(%2,0)
   %endif
  %elif DWordByteIs00(%2,3)&DWordByteIs00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIs00(%2,0) ; 0010
   %ifndef Contained_H
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_H,Byte(%2,1)
   %endif
  %elif DWordByteIs00(%2,3)&DWordByteIs00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIsNot00(%2,0) ; 00??
   %ifndef Contained_W
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_W,Byte(%2,1)<<8|Byte(%2,0)
   %endif
  %elif DWordByteIs00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIs00(%2,1)&DWordByteIs00(%2,0) ; 0?00
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_L,Byte(%2,2)
    shl %1,2*8
   %endif
  %elif DWordByteIs00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIs00(%2,1)&DWordByteIsNot00(%2,0) ; 0?0?
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_L,Byte(%2,2)
    shl %1,2*8
    mov Contained_L,Byte(%2,0)
   %endif
  %elif DWordByteIs00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIs00(%2,0) ; 0??0
   %ifndef Contained_W
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_W,Byte(%2,2)<<8|Byte(%2,1)
    shl %1,8
   %endif
  %elif DWordByteIs00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIsNot00(%2,0) ; 0???
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %elifndef Contained_W
    %define MovD_r_NumId_Recursive_Define 1
   %else
    xor %1,%1
    mov Contained_L,Byte(%2,2)
    shl %1,2*8
    mov Contained_W,Byte(%2,1)<<8|Byte(%2,0)
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIs00(%2,2)&DWordByteIs00(%2,1)&DWordByteIs00(%2,0) ; ?000
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %else
    mov Contained_L,Byte(%2,3)
    shl %1,3*8
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIs00(%2,2)&DWordByteIs00(%2,1)&DWordByteIsNot00(%2,0) ; ?00?
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %else    
    mov Contained_L,Byte(%2,3)
    shl %1,3*8
    mov Contained_L,Byte(%2,0)
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIs00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIs00(%2,0) ; ?0?0
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %elifndef Contained_H
    %define MovD_r_NumId_Recursive_Define 1
   %else
    mov Contained_L,Byte(%2,3)
    shl %1,3*8
    mov Contained_H,Byte(%2,1)
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIs00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIsNot00(%2,0) ; ?0??
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %elifndef Contained_W
    %define MovD_r_NumId_Recursive_Define 1
   %else
    mov Contained_L,Byte(%2,3)
    shl %1,3*8
    mov Contained_W,Byte(%2,1)<<8|Byte(%2,0)
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIs00(%2,1)&DWordByteIs00(%2,0) ; ??00
   %ifndef Contained_W
    %define MovD_r_NumId_Recursive_Define 1
   %else
    mov Contained_W,Byte(%2,3)<<8|Byte(%2,2)
    shl %1,2*8
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIs00(%2,1)&DWordByteIsNot00(%2,0) ; ??0?
   %ifndef Contained_H
    %define MovD_r_NumId_Recursive_Define 1
   %else
    FillByte
    mov %1,Byte(%2,3)<<3*8|Byte(%2,2)<<2*8|FillByte_Ret<<1*8|Byte(%2,0)
    xor Contained_H,Contained_H
   %endif
  %elif DWordByteIsNot00(%2,3)&DWordByteIsNot00(%2,2)&DWordByteIsNot00(%2,1)&DWordByteIs00(%2,0) ; ???0
   %ifndef Contained_L
    %define MovD_r_NumId_Recursive_Define 1
   %else
    FillByte
    mov %1,Byte(%2,3)<<3*8|Byte(%2,2)<<2*8|Byte(%2,1)<<1*8|FillByte_Ret
    xor Contained_L,Contained_L
   %endif
  %endif
 %endif
%endmacro

%macro MovD_r_NumId 2
 %define MovD_r_NumId_Recursive_Define 0
 %define MovD_OriginalRegister_Define %1
 %define MovD_TemporaryRegister_Define %1
 %rep 2
  MovD_r_NumId_Recursive MovD_TemporaryRegister_Define,%2
  %if MovD_r_NumId_Recursive_Define==0 ;si pas d'erreur 1er passage
   %exitrep
  %elif MovD_r_NumId_Recursive_Define==1 ;si erreur 1er passage
   TemporaryBegin dword,-,MovD_OriginalRegister_Define
   %define MovD_TemporaryRegister_Define Temporary_Ret
   %define MovD_r_NumId_Recursive_Define 2
  %elif MovD_r_NumId_Recursive_Define==2 ;si fin 2ème passage
   mov MovD_OriginalRegister_Define,MovD_TemporaryRegister_Define
   TemporaryEnd
   %exitrep
  %endif
 %endrep
 %undef MovD_r_NumId_Recursive_Define
 %undef MovD_OriginalRegister_Define
 %undef MovD_TemporaryRegister_Define
%endmacro

%macro MovW_r_NumId 2
 %if WordContainNo00(%2)
  mov %1,%2
 %elif %2==0
  xor %1,%1
 %else
  Contained %1,word
  MovB_r_NumId Contained_H,Byte(%2,1)
  MovB_r_NumId Contained_L,Byte(%2,0)
 %endif
%endmacro

%macro MovB_r_NumId 2
 %if ByteIsNot00(%2)
  mov %1,%2
 %elif %2==0
  xor %1,%1
 %else
  mov %1,~%2
  not %1
 %endif
%endmacro

%macro Mov_X_NumId 2-3
 %ifndef BYTE.INC_NO_00
  mov %1,%2
 %else
  %if %0==2
   Operand %1
  %else
   Operand %1,%3
  %endif
  %ifndef Operand_Unknown ;mov r,d|w|b
   %ifidni Operand_Size,dword
    MovD_r_NumId %1,%2
   %elifidni Operand_Size,word
    MovW_r_NumId %1,%2
   %elifidni Operand_Size,byte
    MovB_r_NumId %1,%2
   %endif
  %else ;mov [r],d|w|b
   %ifidni Operand_Size,dword
    %if DWordContainNo00(%2)
     mov %1,%2
    %elif DWordContainNo00(~%2)
     mov %1,~%2
     not %1
    %elif DWordContainNo00(-%2)
     mov %1,-%2
     neg %1
    %else
     TemporaryBegin dword
      MovD_r_NumId Temporary_Ret,%2
      mov %1,Temporary_Ret
     TemporaryEnd
    %endif
   %elifidni Operand_Size,word
    %if WordContainNo00(%2)
     mov %1,%2
    %elif WordContainNo00(~%2)
     mov %1,~%2
     not %1
    %elif WordContainNo00(-%2)
     mov %1,-%2
     neg %1
    %else
     TemporaryBegin word
      MovW_r_NumId Temporary_Ret,%2
      mov %1,Temporary_Ret
     TemporaryEnd
    %endif
   %elifidni Operand_Size,byte
    %if ByteIsNot00(%2)
     mov %1,%2
    %else
     mov %1,~%2
     not %1
    %endif
   %else
    %if %0==2
     Error BYTE,Mov %1,%2 => dword|word|byte ?
    %else
     Error BYTE,Mov %1,%2,%3 => dword|word|byte ?
    %endif
   %endif
  %endif
 %endif
%endmacro

%macro Mov_X_Str 2+
 Operand %1
 %ifndef Operand_Unknown
  %ifndef BYTE.INC_NO_00
   call %%Mov_End
   db %2,0
   %%Mov_End: pop %1
  %else
   FillByte
   jmp short %%Mov_Call
   %%Mov_Jmp: jmp short %%Mov_Calculate
   %%Mov_Call: call %%Mov_Jmp
   %%Mov_String: db %2
   %%Mov_StringEnd: times (1+BYTE.INC_FILL_OFFSET) db FillByte_Ret
   %%Mov_Calculate:
   pop %1
   sub byte [byte %1+(%%Mov_StringEnd-%%Mov_String)],FillByte_Ret
  %endif
 %else
  Error BYTE,Mov %1,%2 => eax|ebx|ecx|edx|esi|edi|esp|ebp
 %endif
%endmacro

;Mov r,d|w|b|"string" [,dword|word|byte]
%macro Mov 2+
 %ifstr %2
  Mov_X_Str %1,%2
 %elifnum %2
  Mov_X_NumId %1,%2
 %elifid %2
  Mov_X_NumId %1,%2
 %else
  mov %1,%2
  %ifdef BYTE.INC_NO_00
   Warning BYTE,Mov %1,%2 => 00 ?
  %endif
 %endif
%endmacro

%macro MovD 2
 Mov %1,%2,dword
%endmacro

%macro MovW 2
 Mov %1,%2,word
%endmacro

%macro MovB 2
 Mov %1,%2,byte
%endmacro

;================================== Jump =====================================
%macro Jmp_Num 2
 Warning BYTE,Jmp %1 => Jmp [%1]
 %ifndef BYTE.INC_NO_00
  jmp [%1]
 %elif DWordContainNo00(%1)
  jmp [%1]
 %else
  %ifdef BYTE.INC_TEMPORARY_REGISTER
   Mov BYTE.INC_TEMPORARY_REGISTER,%1
   jmp [BYTE.INC_TEMPORARY_REGISTER]
  %else
   TemporaryBegin dword,+,edx ;eax => 00
    Mov Temporary_Ret,%1
    mov Temporary_Ret,[Temporary_Ret]
    mov [esp-4],Temporary_Ret ;dword temporaire
   TemporaryEnd
   jmp [esp-Temporary_esp-4]
  %endif
 %endif
%endmacro

%macro Jmp_Id 2
 %ifndef BYTE.INC_LONG_JUMP
  jmp short %1
 %elifndef BYTE.INC_NO_00
  jmp %1
 %elif %2==-1
  jmp %1
 %else ;jump long vers l'avant
  jmp short %%Jmp_Call
  %%Jmp_Calculate:
   TemporaryBegin dword
    mov Temporary_Ret,~(%1-%%Jmp_End)
    not Temporary_Ret
    add dword [esp+Temporary_esp],Temporary_Ret
   TemporaryEnd
   ret
   FillByte
   times BYTE.INC_FILL_OFFSET db FillByte_Ret
  %%Jmp_Call: call %%Jmp_Calculate
  %%Jmp_End:
 %endif
%endmacro

%macro Jmp 1-2 BYTE.INC_JUMP_DIRECTION
 %ifndef Alias_%1
  %ifnum %1
   Jmp_Num %1,%2
  %elifid %1
   Jmp_Id %1,%2
  %else
   jmp %1
   %ifdef BYTE.INC_NO_00
    Warning BYTE,Jmp %1 => 00 ?
   %endif
  %endif
 %else
  jmp Alias_%1
  %ifdef BYTE.INC_NO_00
   Warning BYTE,Jmp %1 => 00 ?
  %endif
 %endif
%endmacro

%macro JX 2-3 BYTE.INC_JUMP_DIRECTION ;support for jX near (386+)
 %ifndef BYTE.INC_LONG_JUMP
  j%+1 %2
 %else
  j%-1 %%JX_End
  Jmp %2,%3
  FillByte
  times BYTE.INC_FILL_OFFSET db FillByte_Ret
  %%JX_End:
 %endif
%endmacro

%macro JnX 2-3 BYTE.INC_JUMP_DIRECTION ;support for jnX near (386+)
 %ifndef BYTE.INC_LONG_JUMP
  j%-1 %2
 %else
  j%+1 %%JnX_End
  Jmp %2,%3
  FillByte
  times BYTE.INC_FILL_OFFSET db FillByte_Ret
  %%JnX_End:
 %endif
%endmacro

;================================== Call =====================================
%macro Call_Num 2
 Warning BYTE,Call %1 => Call [%1]
 %ifndef BYTE.INC_NO_00
  call [%1]
 %elif DWordContainNo00(%1)
  call [%1]
 %else
  %ifdef BYTE.INC_TEMPORARY_REGISTER
   Mov BYTE.INC_TEMPORARY_REGISTER,%1
   call [BYTE.INC_TEMPORARY_REGISTER]
  %else
   TemporaryBegin dword,+,edx ;eax => 00
    Mov Temporary_Ret,%1
    mov Temporary_Ret,[Temporary_Ret]
    mov [esp-4],Temporary_Ret ;dword temporaire
   TemporaryEnd
   call [esp-Temporary_esp-4]
  %endif
 %endif
%endmacro

%macro Call_Id 2
 %ifndef BYTE.INC_NO_00
  call %1
 %elif %2==-1
  call %1
 %else
  jmp short %%Call_Call1
  %%Call_Calculate:
   push dword [esp]
   TemporaryBegin dword
    mov Temporary_Ret,~(%1-%%Call_End)
    not Temporary_Ret
    add dword [esp+Temporary_esp],Temporary_Ret
   TemporaryEnd
   ret
   FillByte
   times BYTE.INC_FILL_OFFSET db FillByte_Ret
  %%Call_Call1: call %%Call_Calculate
  %%Call_End:
 %endif
%endmacro

%macro Call 1-2 BYTE.INC_JUMP_DIRECTION
 %ifndef Alias_%1
  %ifnum %1
   Call_Num %1,%2
  %elifid %1
   Call_Id %1,%2
  %else
   call %1
   %ifdef BYTE.INC_NO_00
    Warning BYTE,Call %1 => 00 ?
   %endif
  %endif
 %else
  call Alias_%1
  %ifdef BYTE.INC_NO_00
   Warning BYTE,Call %1 => 00 ?
  %endif
 %endif
%endmacro

;================================== Push =====================================
%macro Push_Num 1
 %ifndef BYTE.INC_NO_00
  push dword %1
 %elif DWordContainNo00(%1)
  push dword %1
 %else
  TemporaryBegin dword,-,push
   Mov Temporary_Ret,%1
   push Temporary_Ret
  TemporaryEnd
 %endif
%endmacro

%macro Push_Id 1
 TemporaryBegin dword,-,push
  mov Temporary_Ret,%1
  push Temporary_Ret
 TemporaryEnd
 %ifdef BYTE.INC_NO_00
  Warning BYTE,Push %1 => 00 ?
 %endif
%endmacro

%macro Push_Str 1+
 %ifndef BYTE.INC_NO_00
  call %%Push_End
  db %1,0
  %%Push_End:
 %else
  FillByte
  jmp short %%Push_Call
  %%Push_Jmp: jmp short %%Push_Calculate
  %%Push_Call: call %%Push_Jmp
  %%Push_String: db %1
  %%Push_StringEnd: times (1+BYTE.INC_FILL_OFFSET) db FillByte_Ret
  %%Push_Calculate:
  TemporaryBegin dword,-,push
   mov Temporary_Ret,[esp]
   sub byte [byte Temporary_Ret+(%%Push_StringEnd-%%Push_String)],FillByte_Ret
  TemporaryEnd
 %endif
%endmacro

%macro Push 1+
 Operand %1
 %ifdef Operand_Container ;r
  push Operand_Container
 %elifnum %1
  Push_Num %1
 %elifid %1
  Push_Id %1
 %elifstr %1
  Push_Str %1
 %else
  push %1
  %ifdef BYTE.INC_NO_00
   Warning BYTE,Push %1 => 00 ?
  %endif
 %endif
%endmacro

;=============================== Instructions ================================
%macro Instruction_r_NumId_size 4
 TemporaryBegin %4,-,%2
  Mov Temporary_Ret,%3
  %1 %2,Temporary_Ret
 TemporaryEnd
%endmacro

%macro Instruction_r_NumId 3
 Operand %2
 %ifdef Operand_Size
  %ifidni Operand_Size,dword
   %if DWordContainNo00(%3)
    %1 %2,%3
   %else
    Instruction_r_NumId_size %1,%2,%3,Operand_Size
   %endif
  %elifidni Operand_Size,word
   %if WordContainNo00(%3)
    %1 %2,%3
   %else
    Instruction_r_NumId_size %1,%2,%3,Operand_Size
   %endif
  %elifidni Operand_Size,byte
   %if ByteIsNot00(%3)
    %1 %2,%3
   %else
    Instruction_r_NumId_size %1,%2,%3,Operand_Size
   %endif
  %endif
 %else
  %1 %2,%3
  %ifdef BYTE.INC_NO_00
   Warning BYTE,%1 %2,%3 => 00 ?
  %endif
 %endif
%endmacro

;Instruction_r_X instruction,r,*
%macro Instruction_r_X 3
 %ifndef BYTE.INC_NO_00
  %1 %2,%3
 %elifnum %3
  Instruction_r_NumId %1,%2,%3
 %elifid %3
  Instruction_r_NumId %1,%2,%3
 %else
  %1 %2,%3
 %endif 
%endmacro

;================================= Autres ====================================
%macro Add 2
 Operand %1
 %ifndef Operand_Unknown
  %if %2<=6
   %rep %2
    inc %1
   %endrep
  %else
   Instruction_r_X add,%1,%2
  %endif
 %else
  Instruction_r_X add,%1,%2
 %endif
%endmacro

%macro And 2
 Instruction_r_X and,%1,%2
%endmacro

%macro Cmp 2
 Instruction_r_X cmp,%1,%2
%endmacro

%macro Or 2
 Instruction_r_X or,%1,%2
%endmacro

%macro Sub 2
 Operand %1
 %ifndef Operand_Unknown
  %if %2<=6
   %rep %2
    dec %1
   %endrep
  %else
   Instruction_r_X sub,%1,%2
  %endif
 %else
  Instruction_r_X sub,%1,%2
 %endif
%endmacro

%macro Xor 2
 Instruction_r_X xor,%1,%2
%endmacro

%endif
