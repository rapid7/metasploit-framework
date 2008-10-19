#!/usr/bin/env ruby -I..

=begin

The Metasploit Rex library is provided under the 3-clause BSD license.

Copyright (c) 2005-2006, Metasploit LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this 
   list of conditions and the following disclaimer.
   
 * Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.
   
 * Neither the name of Metasploit LLC nor the names of its contributors may be 
   used to endorse or promote products derived from this software without 
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

require 'test/unit'

require 'rex/exceptions.rb.ut'
require 'rex/transformer.rb.ut'
require 'rex/text.rb.ut'
require 'rex/file.rb.ut'

require 'rex/encoder/xdr.rb.ut'

require 'rex/encoding/xor/generic.rb.ut'
require 'rex/encoding/xor/byte.rb.ut'
require 'rex/encoding/xor/word.rb.ut'
require 'rex/encoding/xor/dword.rb.ut'
require 'rex/encoding/xor/dword_additive.rb.ut'

require 'rex/socket.rb.ut'
require 'rex/socket/tcp.rb.ut'
require 'rex/socket/ssl_tcp.rb.ut'
require 'rex/socket/tcp_server.rb.ut'
require 'rex/socket/udp.rb.ut'
require 'rex/socket/parameters.rb.ut'
require 'rex/socket/comm/local.rb.ut'
require 'rex/socket/switch_board.rb.ut'
require 'rex/socket/subnet_walker.rb.ut'

require 'rex/proto.rb.ts'

require 'rex/parser/arguments.rb.ut'

require 'rex/ui/text/color.rb.ut'
require 'rex/ui/text/table.rb.ut'

require 'rex/exploitation/egghunter.rb.ut'
require 'rex/exploitation/seh.rb.ut'