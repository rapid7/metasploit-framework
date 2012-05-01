require 'mkmf'
require './version.rb'
$CFLAGS << %[ -I.. -Wall -O3 -DMESSAGEPACK_VERSION=\\"#{MessagePack::VERSION}\\" -g]
create_makefile('msgpack')

