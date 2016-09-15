# -*- coding: binary -*-
=begin

The Metasploit Rex library is provided under the 3-clause BSD license.

Copyright (c) 2005-2014, Rapid7, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this 
   list of conditions and the following disclaimer.
   
 * Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.
   
 * Neither the name of Rapid7, Inc. nor the names of its contributors may be 
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

module Rex
  Root = File.join(File.expand_path(File.dirname(__FILE__)), 'rex')
  LogSource = "rex"
end

#
# REX Gems
#
# Text manipulation library for things like generating random string
require 'rex/text'
# Library for Generating Randomized strings valid as Identifiers such as variable names
require 'rex/random_identifier'
# library for creating Powershell scripts for exploitation purposes
require 'rex/powershell'
# Library for processing and creating Zip compatbile archives
require 'rex/zip'
# Library for parsing offline Windows Registry files
require 'rex/registry'
# Library for parsing Java serialized streams
require 'rex/java'
# Library for creating C-style Structs
require 'rex/struct2'
# Library for working with OLE
require 'rex/ole'
# Library for creating and/or parsing MIME messages
require 'rex/mime'

# Generic classes
require 'rex/exceptions'
require 'rex/transformer'
require 'rex/random_identifier'
require 'rex/text'
require 'rex/time'
require 'rex/job_container'
require 'rex/file'

# Thread safety and synchronization
require 'rex/sync'

# Thread factory
require 'rex/thread_factory'

# Encoding
require 'rex/encoder/xor'
require 'rex/encoding/xor'

# Architecture subsystem
require 'rex/arch'

# Assembly
require 'rex/assembly/nasm'

# Logging
require 'rex/logging/log_dispatcher'

# IO
require 'rex/io/stream'
require 'rex/io/stream_abstraction'
require 'rex/io/stream_server'

# Sockets
require 'rex/socket'

# Protocols
require 'rex/proto'
require 'rex/mac_oui'

# Parsers
require 'rex/parser/arguments'
require 'rex/parser/ini'


# Compatibility
require 'rex/compat'

# Platforms
require 'rex/platforms'

# SSLScan 
require 'rex/sslscan/scanner'
require 'rex/sslscan/result'


# Overload the Kernel.sleep() function to be thread-safe
Kernel.class_eval("
  def sleep(seconds=nil)
    Rex::ThreadSafe.sleep(seconds)
  end
")

# Overload the Kernel.select function to be thread-safe
Kernel.class_eval("
  def select(rfd = nil, wfd = nil, efd = nil, to = nil)
    Rex::ThreadSafe.select(rfd, wfd, efd, to)
  end
")
