;                       GENERAL MACROS FOR NASM v1.0a
;                       =============================


;NASM.INC_NO_WARNING => ne pas afficher les warnings utilisateurs


;Error include(sans .INC),message
;Warning include(sans .INC),message

;MultiParams p
; -> MultiParams_Ret = nombre de paramètres

;================================= General ===================================
%ifndef _NASM.INC
%define _NASM.INC

%push _NASM.INC ;pour éviter erreurs %ifctx

%macro NASM.INC 0
 %undef NASM.INC_NO_WARNING
 %assign ErrorWarning_Assign 0
%endmacro

%macro NASM.INC~ 0
 NASM.INC
%endmacro

NASM.INC

%macro Error 2+
 ErrorWarningNext
 %error %1.INC error: %2
%endmacro

%macro Warning 2+
 %ifndef NASM.INC_NO_WARNING
  ErrorWarningNext
  %error %1.INC warning: %2
 %endif
%endmacro

%macro ErrorWarningNext 0
 %assign ErrorWarning_Assign ErrorWarning_Assign+1
 %if ErrorWarning_Assign==1
  %error ===============================================
 %endif
%endmacro

%macro MultiParams 1-*
 %define MultiParams_Ret %0
%endmacro

%endif
