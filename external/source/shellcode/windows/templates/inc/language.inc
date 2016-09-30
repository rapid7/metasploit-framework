;                 MACROS FOR STRUCTURATED PROGRAMMING v0.9a
;                 =========================================


;Continue
;Break

;IfJmp {valeur1},condition,valeur2,l [,-1|+1]
;IfNotJmp {valeur1},condition,valeur2,l [,-1|+1]
;If {valeur1},condition,valeur2
;IfX condition asm
; ...
;[Else]
; [...]
;EndIf

;Switch v
;Case v1
;...
;[Default]
; [...]
;EndSwitch
; les conditions Case sont évaluées juste avant leur exécution, à la
; différence du C !!!

;While [{valeur1},condition,valeur2]
; ...
;EndWhile [{valeur1},condition,valeur2]

;Until [{valeur1},condition,valeur2]
; ...
;EndUntil [{valeur1},condition,valeur2]

;For compteur,valeur_début,condition,valeur_fin,valeur_incrément
; ...
;EndFor

;================================= General ===================================
%ifndef _LANGUAGE.INC
%define _LANGUAGE.INC

%include "byte.inc"

;============================= Continue-Break ================================
%macro Continue 0
 %ifdef %$BeginEnd
  Jmp %$Begin,-1
 %elifdef %$$BeginEnd
  Jmp %$$Begin,-1
 %elifdef %$$$BeginEnd
  Jmp %$$$Begin,-1
 %elifdef %$$$$BeginEnd
  Jmp %$$$$Begin,-1
 %elifdef %$$$$$BeginEnd
  Jmp %$$$$$Begin,-1
 %elifdef %$$$$$$BeginEnd
  Jmp %$$$$$$Begin,-1
 %elifdef %$$$$$$$BeginEnd
  Jmp %$$$$$$$Begin,-1
 %elifdef %$$$$$$$$BeginEnd
  Jmp %$$$$$$$$Begin,-1
 %elifdef %$$$$$$$$$BeginEnd
  Jmp %$$$$$$$$$Begin,-1
 %elifdef %$$$$$$$$$$BeginEnd
  Jmp %$$$$$$$$$$Begin,-1
 %else
  Error LANGUAGE,Continue => 10 blocs maximum
 %endif
%endmacro

%macro Break 0
 %ifdef %$BeginEnd
  Jmp %$End,+1
 %elifdef %$$BeginEnd
  Jmp %$$End,+1
 %elifdef %$$$BeginEnd
  Jmp %$$$End,+1
 %elifdef %$$$$BeginEnd
  Jmp %$$$$End,+1
 %elifdef %$$$$$BeginEnd
  Jmp %$$$$$End,+1
 %elifdef %$$$$$$BeginEnd
  Jmp %$$$$$$End,+1
 %elifdef %$$$$$$$BeginEnd
  Jmp %$$$$$$$End,+1
 %elifdef %$$$$$$$$BeginEnd
  Jmp %$$$$$$$$End,+1
 %elifdef %$$$$$$$$$BeginEnd
  Jmp %$$$$$$$$$End,+1
 %elifdef %$$$$$$$$$$BeginEnd
  Jmp %$$$$$$$$$$End,+1
 %else
  Error LANGUAGE,Break => 10 blocs maximum
 %endif
%endmacro

;==================================== If =====================================
%macro IfJmp 4+
 MultiParams %1
 %if MultiParams_Ret==1
  Cmp %1,%3
 %else
  %1
  Cmp eax,%3
 %endif
 %ifidni %2,==
  JX e,%4
 %elifidni %2,!=
  JX ne,%4
 %elifidni %2,<
  JX b,%4
 %elifidni %2,>
  JX a,%4
 %elifidni %2,<=
  JX be,%4
 %elifidni %2,>=
  JX ae,%4
 %else
  Error LANGUAGE,IfJmp v1,condition,v2,label
 %endif
%endmacro

%macro IfNotJmp 4+
 MultiParams %1
 %if MultiParams_Ret==1
  Cmp %1,%3
 %else
  %1
  Cmp eax,%3
 %endif
 %ifidni %2,==
  JX ne,%4
 %elifidni %2,!=
  JX e,%4
 %elifidni %2,<
  JX ae,%4
 %elifidni %2,>
  JX be,%4
 %elifidni %2,<=
  JX a,%4
 %elifidni %2,>=
  JX b,%4
 %else
  Error LANGUAGE,IfNotJmp v1,condition,v2,label
 %endif
%endmacro


%macro If 3
 %push If
 MultiParams %1
 %if MultiParams_Ret==1
  IfNotJmp %1,%2,%3,%$If_Not,+1
 %else
  IfNotJmp {%1},%2,%3,%$If_Not,+1
 %endif
%endmacro

%macro IfX 1
 %push If
 JnX %1,%$If_Not,+1
%endmacro

%macro Else 0
 %ifctx If
  Jmp %$If_End,+1
  %$If_Not:
  %repl Else
 %else
  Error LANGUAGE,Else => If | IfX
 %endif
%endmacro

%macro EndIf 0
 %ifctx If
  %$If_Not:
  %pop
 %elifctx Else
  %$If_End:
  %pop
 %else
  Error LANGUAGE,EndIf => If | IfX | Else
 %endif
%endmacro

;================================== Switch ===================================
%macro Switch 1
 %push Switch
 %define %$BeginEnd
 %define %$Switch_V_Define %1
 %$Begin:
%endmacro

%macro Case 1
 %ifdef %$Switch_NeedEndIf_Define
  EndIf
 %endif
 %ifctx Switch
  If %$Switch_V_Define,==,%1
  %define %$Switch_NeedEndIf_Define
 %else
  Error LANGUAGE,Case => Switch
 %endif
%endmacro

%macro Default 0
 %ifdef %$Switch_NeedEndIf_Define
  EndIf
 %endif
 %ifctx Switch
 %else
  Error LANGUAGE,Default => Switch
 %endif
%endmacro

%macro EndSwitch 0
 %ifdef %$Switch_NeedEndIf_Define
  EndIf
 %endif
 %ifctx Switch
  %$End:
  %pop
 %else
  Error LANGUAGE,EndSwitch => Switch
 %endif
%endmacro

;================================== While ====================================
%macro While 0-3
 %push While
 %define %$BeginEnd
 %$Begin:
 %if %0!=0
  MultiParams %1
  %if MultiParams_Ret==1
   IfNotJmp %1,%2,%3,%$End,+1  
  %else
   IfNotJmp {%1},%2,%3,%$End,+1  
  %endif
 %endif
%endmacro

%macro EndWhile 0-3
 %ifctx While
  %if %0!=0
   MultiParams %1
   %if MultiParams_Ret==1
    IfJmp %1,%2,%3,%$Begin,-1
   %else
    IfJmp {%1},%2,%3,%$Begin,-1
   %endif
  %else
   Continue
  %endif
  %$End:
  %pop
 %else
  Error LANGUAGE,EndWhile => While
 %endif
%endmacro

;================================== Until ====================================
%macro Until 0-3
 %push Until
 %define %$BeginEnd
 %$Begin:
 %if %0!=0
  MultiParams %1
  %if MultiParams_Ret==1
   IfJmp %1,%2,%3,%$End,+1
  %else
   IfJmp {%1},%2,%3,%$End,+1
  %endif
 %endif
%endmacro

%macro EndUntil 0-3
 %ifctx Until
  %if %0!=0
   MultiParams %1
   %if MultiParams_Ret==1
    IfNotJmp %1,%2,%3,%$Begin,-1
   %else
    IfNotJmp {%1},%2,%3,%$Begin,-1
   %endif
  %else
   Continue
  %endif
  %$End:
  %pop
 %else
  Error LANGUAGE,EndUntil => Until
 %endif
%endmacro

;=================================== For =====================================
%macro For 5
 %push For
 %define %$BeginEnd
 %define %$For_1_Define %1
 %define %$For_5_Define %5
 Mov %1,%2
 %$Begin:
 MultiParams %1
 %if MultiParams_Ret==1
  IfNotJmp %1,%3,%4,%$End,+1
 %else
  IfNotJmp {%1},%3,%4,%$End,+1
 %endif
%endmacro

%macro EndFor 0
 %ifctx For
  %if %$For_5_Define>0
   Add %$For_1_Define,%$For_5_Define
  %elif %$For_5_Define<0
   Sub %$For_1_Define,-%$For_5_Define
  %else
  %endif
  Continue
  %$End:
  %pop
 %else
  Error LANGUAGE,EndFor => For
 %endif
%endmacro

%endif
