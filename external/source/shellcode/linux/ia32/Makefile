STAGERS=stager_sock_bind stager_sock_bind6 stager_sock_bind_udp stager_sock_bind_icmp \
        stager_egghunt stager_sock_find stager_sock_reverse \
        stager_sock_reverse_icmp stager_sock_reverse_udp \
				stager_sock_reverse_udp_dns
STAGES=stage_tcp_shell stage_udp_shell
SINGLE=single_adduser single_bind_tcp_shell single_find_tcp_shell \
       single_reverse_tcp_shell single_reverse_udp_shell single_exec

OBJS=${STAGERS} ${STAGES} ${SINGLE}

.SUFFIXES:
.SUFFIXES: .asm .hex .disasm .o

# Tell Make not to delete these intermediate files
.PRECIOUS: %.hex %.disasm

all: $(SINGLE) $(STAGES) $(STAGERS)

%.o: %.asm %.bin %.hex %.disasm
	@nasm -o $@ -f elf $<

%.bin: %.asm
	@nasm -o $@ -f bin $<

# Replace 00 with \x00.  Put quotes at beginning and end of line.  Put plus at
# end of all lines but the last.  This ends up outputting an escaped string
# suitable for use in a Ruby script.
%.hex: %.bin
	@xxd -c 16 -ps $< | \
		sed -e 's/\([0123456789abcdef][0123456789abcdef]\)/\\x\1/g' \
		-e 's/^/"/;s/$$/"/;$$ b;s/$$/+/;' > $@

# ljust(23) because the longest instruction is usually 5 bytes which takes 22
# characters including quotes
%.disasm: %.bin
	@ndisasm -b 32 $< > $*.tmp
	@ruby -p -a -e ' \
		$$F.shift; \
		$$F[0].tap { |s| \
			s.tr! "A-F", "a-f"; \
			t=s.dup; \
			s.clear; \
			s<<("\""+t.scan(/../).map{|b|"\\x#{b}"}.join+"\"").ljust(23); \
			STDIN.eof? ? s<< " #  " : s<< "+#  "; \
		}; \
		$$_ = $$F.join(" ") + "\n"; \
		' < $*.tmp > $@
	@rm $*.tmp

$(SINGLE) $(STAGES) $(STAGERS): %: %.o
	@echo "Building $@... (`wc -c $(<:.o=.bin)|awk '{print $$1}'` bytes)"
	@ld -i -m elf_i386 $< -o $@
	@chmod +x $@


clean:
	rm -f *.bin *.tmp *.o *.hex ${OBJS} *.disasm
