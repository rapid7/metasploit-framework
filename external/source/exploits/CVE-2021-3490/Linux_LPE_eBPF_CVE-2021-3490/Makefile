CC=gcc
LPE =lpe

BIN = bin/
INC = include/

CMP = -o $(BIN)exploit.bin -I $(INC) exploit.c bpf.c kmem_search.c

groovy: 
	$(CC) -DGROOVY $(CMP)

hirsute: 
	$(CC) -DHIRSUTE $(CMP)

clean:
	rm $(BIN)exploit.bin
