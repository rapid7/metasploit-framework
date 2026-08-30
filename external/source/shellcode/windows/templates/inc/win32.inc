;                     MACROS FOR WIN32 PROGRAMMING v1.0a
;                     ==================================


;WIN32.INC_NO_EXTERN_IMPORT => pas d'Import


;ExternImport function,dll [,d|[*]]
; <- FUNCTION.INC_CONVENTION

;================================= General ===================================
%ifndef _WIN32.INC
%define _WIN32.INC

%include "function.inc"
%include "language.inc"
%include "win32n.inc"
%include "win32dll.inc"

%macro WIN32.INC 0
 FUNCTION.INC
 %undef WIN32.INC_NO_EXTERN_IMPORT
%endmacro

%macro WIN32.INC~ 0
 FUNCTION.INC~
 %undef WIN32.INC_NO_EXTERN_IMPORT
%endmacro

WIN32.INC

%macro ExternImport 2-3
 %ifndef ExternImport_%1
  %ifndef WIN32.INC_NO_EXTERN_IMPORT
   extern %1
   import %1 %2
   Alias @%1,[%1]
   FunctionDefine %1,FUNCTION.INC_CONVENTION
  %else
   %if %0==3
    %ifnum %3
     FunctionDefine %1,FUNCTION.INC_CONVENTION,%3
    %else
     Alias @%1,%3
     FunctionDefine %1,FUNCTION.INC_CONVENTION
    %endif
   %else
    Error WIN32,NO_EXTERN_IMPORT => ExternImport %1,%2,d|[*]
   %endif
  %endif
  %define ExternImport_%1
 %endif
%endmacro

%endif
