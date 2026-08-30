;                   MACROS FOR FUNCTION DECLARATIONS v0.9a
;                   ======================================


;gérer les appels de fonctions externes C (linux)
;return() ?


;FUNCTION.INC_CONVENTION = C|Std = convention d'appel des fonctions par défaut


;FunctionDefine alias,C|Std|Pascal [,adresse]
; -> FunctionDefine_alias = C|Std|Pascal
;    @alias = adresse de la fonction
;    alias$  (si aucun paramètre)
;    alias([p1,...])  (si plusieurs paramètres)

;Function alias, [,p1,...]
; <- FunctionDefine
; -> @alias = adresse de la fonction
;    Function_EBP ebp
;    Function_EIP byte ebp+4
;[FunctionResd nom,nombre d]
;[FunctionResw nom,nombre w]
;[FunctionResb nom,nombre b]
;...
;FunctionBegin
; <- Sub
; ...
;FunctionEnd
; <- FUNCTION.INC_CONVENTION,BYTE.INC_NO_00

;FunctionCall alias, [,p1,...]
; <- Push,Call,BYTE.INC_TEMPORARY_REGISTER(push & pop C)

;================================= General ===================================
%ifndef _FUNCTION.INC
%define _FUNCTION.INC

%include "byte.inc"

%macro FUNCTION.INC 0
 BYTE.INC
 %define FUNCTION.INC_CONVENTION C
%endmacro

%macro FUNCTION.INC~ 0
 BYTE.INC~
 %define FUNCTION.INC_CONVENTION C
%endmacro

FUNCTION.INC

%macro FunctionDefine 2-3
 %define FunctionDefine_%1 %2
 %if %0==3
  %ifnidni %3,@%1
   %define @%1 %3
  %endif
 %endif
 %define %1$ FunctionCall %1
 %define %1(p1) FunctionCall %1,p1
 %define %1(p1,p2) FunctionCall %1,p1,p2
 %define %1(p1,p2,p3) FunctionCall %1,p1,p2,p3
 %define %1(p1,p2,p3,p4) FunctionCall %1,p1,p2,p3,p4
 %define %1(p1,p2,p3,p4,p5) FunctionCall %1,p1,p2,p3,p4,p5
 %define %1(p1,p2,p3,p4,p5,p6) FunctionCall %1,p1,p2,p3,p4,p5,p6
 %define %1(p1,p2,p3,p4,p5,p6,p7) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19
 %define %1(p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20) FunctionCall %1,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20
%endmacro

;================================= Function ==================================
%macro Function 1-*
 FUNCTION.INC~
 %ifndef Function_%1
  %ifctx Function
   Error FUNCTION,Function =X=> Function
  %else
   %push Function
   %define Function_%1
   %define Function_Name_Define @%1
   %ifndef BYTE.INC_NO_00
    %define Function_EBP byte ebp
   %endif
   %define Function_EIP byte ebp+4
   FunctionDefine %1,FUNCTION.INC_CONVENTION
   %assign Function_Params_Assign 4
   %if %0>1
    %rotate 1
    %rep %0-1
     %assign Function_Params_Assign Function_Params_Assign+4
     %1_Equ equ Function_Params_Assign
     %define %1 byte ebp+%1_Equ
     %rotate 1
    %endrep
   %endif
   %assign Function_Locals_Assign 0
  %endif
  %undef Function_Exist_Define
 %else
  %define Function_Exist_Define
 %endif
%endmacro

%macro FunctionResd 2
 %ifndef Function_Exist_Define
  %ifctx Function
   %assign Function_Locals_Assign Function_Locals_Assign+%2*4
   %1_Equ equ Function_Locals_Assign
   %if (Function_Locals_Assign < 256)
    %define %1 byte ebp-%1_Equ
   %else
    %define %1 dword ebp-%1_Equ
    %ifdef BYTE.INC_NO_00
     Warning FUNCTION,FunctionResd %1,%2 => 00 ?
    %endif
   %endif
  %else
   Error FUNCTION,FunctionResd => Function
  %endif
 %endif
%endmacro

%macro FunctionResw 2
 %ifndef Function_Exist_Define
  %ifctx Function
   %assign Function_Locals_Assign Function_Locals_Assign+%2*2
   %1_Equ equ Function_Locals_Assign
   %if (Function_Locals_Assign < 256)
    %define %1 byte ebp-%1_Equ
   %else
    %define %1 dword ebp-%1_Equ
    %ifdef BYTE.INC_NO_00
     Warning FUNCTION,FunctionResw %1,%2 => 00 ?
    %endif
   %endif
  %else
   Error FUNCTION,FunctionResw => Function
  %endif
 %endif
%endmacro

%macro FunctionResb 2
 %ifndef Function_Exist_Define
  %ifctx Function
   %assign Function_Locals_Assign Function_Locals_Assign+%2
   %1_Equ equ Function_Locals_Assign
   %if (Function_Locals_Assign < 256)
    %define %1 byte ebp-%1_Equ
   %else
    %define %1 dword ebp-%1_Equ
    %ifdef BYTE.INC_NO_00
     Warning FUNCTION,FunctionResb %1,%2 => 00 ?
    %endif
   %endif
  %else
   Error FUNCTION,FunctionResb => Function
  %endif
 %endif
%endmacro

%macro FunctionBegin 0
 %ifndef Function_Exist_Define
  %ifctx Function
   Function_Name_Define:
   %define BYTE.INC_TEMPORARY_REGISTER eax
   %if (Function_Params_Assign>4)||(Function_Locals_Assign>0)
    push ebp
    mov ebp,esp
   %endif
   %if Function_Locals_Assign>0
    Sub esp,Function_Locals_Assign
   %endif
;   enter Function_Locals_Assign,0
   %undef BYTE.INC_TEMPORARY_REGISTER
  %else
   Error FUNCTION,FunctionBegin => Function
  %endif
 %endif
%endmacro

%macro FunctionEnd 0
 %ifndef Function_Exist_Define
  %ifctx Function
   %if (Function_Params_Assign>4)||(Function_Locals_Assign>0)
    leave
   %endif
   %ifnidni FUNCTION.INC_CONVENTION,C
    %if Function_Params_Assign==4
     ret
    %elifndef BYTE.INC_NO_00
     ret Function_Params_Assign-4
    %else
     Error FUNCTION,NO_00 =X=> CONVENTION Std
    %endif
   %else
    ret
   %endif
   %undef Function_Name_Define
   %pop
  %else
   Error FUNCTION,FunctionEnd => Function
  %endif
 %endif
 %undef Function_Exist_Define
 FUNCTION.INC~
%endmacro

;=================================== Call ====================================
%macro FunctionCallStd 1-*
 %define BYTE.INC_TEMPORARY_REGISTER eax
 %rep %0-1
  %rotate -1
  Push %1
 %endrep
 Call FunctionCall_Address_Define
 %undef BYTE.INC_TEMPORARY_REGISTER
%endmacro

%macro FunctionCallPascal 1-*
 %define BYTE.INC_TEMPORARY_REGISTER eax
 %rep %0-1
  %rotate 1
  Push %1
 %endrep
 Call FunctionCall_Address_Define
 %undef BYTE.INC_TEMPORARY_REGISTER
%endmacro

%macro FunctionCallC 1-*
 %ifndef BYTE.INC_NO_00
  %define BYTE.INC_TEMPORARY_REGISTER eax
 %else
  %ifdef BYTE.INC_TEMPORARY_REGISTER
   %ifidni BYTE.INC_TEMPORARY_REGISTER,eax
    Error FUNCTION,NO_00 => TEMPORARY_REGISTER <> eax
   %endif
  %else
   Error FUNCTION,NO_00 => TEMPORARY_REGISTER
  %endif
 %endif
 %rep %0-1
  %rotate -1
  Push %1
 %endrep
 Call FunctionCall_Address_Define
 %if %0>1
  %ifndef BYTE.INC_NO_00
   %assign FunctionCallC_Assign (%0-1)*4
   add esp,FunctionCallC_Assign
   %undef BYTE.INC_TEMPORARY_REGISTER
  %else
   %ifdef BYTE.INC_TEMPORARY_REGISTER
    %rep %0-1
     pop BYTE.INC_TEMPORARY_REGISTER
    %endrep
   %else
    Error FUNCTION,NO_00 => TEMPORARY_REGISTER
   %endif
  %endif
 %endif
%endmacro

;FunctionCall nom fonction [,p1,...]
%macro FunctionCall 1-2+
 %ifdef FunctionDefine_%1
  %define FunctionCall_Address_Define @%1
  %ifidni FunctionDefine_%1,Std
   %if %0==1
    FunctionCallStd %1
   %else
    FunctionCallStd %1,%2
   %endif
  %elifidni FunctionDefine_%1,Pascal
   %if %0==1
    FunctionCallPascal %1
   %else
    FunctionCallPascal %1,%2
   %endif
  %else
   %if %0==1
    FunctionCallC %1
   %else
    FunctionCallC %1,%2
   %endif
  %endif
  %undef FunctionCall_Address_Define
 %else
  %if %0==1
   Error FUNCTION,FunctionCall %1
  %else
   Error FUNCTION,FunctionCall %1,%2
  %endif
 %endif
%endmacro

%endif
