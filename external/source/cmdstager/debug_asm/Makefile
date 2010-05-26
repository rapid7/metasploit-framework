all: h2b_stub

h2b_stub: h2b_asm
	cat h2b_asm | \
		sed 's/^/echo /g' | \
		sed 's/$$/ >>decoder_stub/g' | \
		sed 's/echo  /echo  /g'> h2b_stub

h2b_asm: h2b.com.dbg
	cat h2b.com.dbg | \
		sed 's/\;.*$$//g' | \
		grep -v ^''$$ | \
		tr -d '\r' | \
		sed 's/ *$$//g' > h2b_asm

h2b.com.dbg:
	./fix_up.rb > h2b.com.dbg
	unix2dos h2b.com.dbg
	chmod 644 h2b.com.dbg

clean:
	rm -f h2b.com.dbg h2b_asm h2b_stub
