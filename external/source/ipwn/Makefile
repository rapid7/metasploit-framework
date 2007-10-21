SRC	= cmd_base.c cmd_expl.c cmd_fd.c cmd_fs.c cmd_misc.c \
      cmd_privs.c cmd_proc.c cmd_sys.c cmd_net.c \
      main.c misc.c

CC=arm-apple-darwin-gcc  	  
CFLAGS=-Wall -s -DMACOSX

BIN	= $(SRC:.c=.o)

all: clean ${BIN} ipwn

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c

ipwn:
	$(CC) $(CFLAGS) $(LDFLAGS) -o ipwn *.o
clean:
	rm -f ipwn *.o
