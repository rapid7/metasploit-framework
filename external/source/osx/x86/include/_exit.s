_exit:
        ;; Exit cleanly
        xor     eax, eax
        push    eax     ; EXIT_SUCCESS
        push    eax     ; spacer
       	inc	eax 
        int     0x80
