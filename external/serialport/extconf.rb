require 'mkmf'

printf("checking for OS... ")
STDOUT.flush
os = /-([a-z]+)/.match(RUBY_PLATFORM)[1]
puts(os)
$CFLAGS += " -D#{os}"

if !(os == 'mswin' or os == 'bccwin')
  exit(1) if not have_header("termios.h") or not have_header("unistd.h")
end

create_makefile("serialport")
