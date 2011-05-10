=begin

The Metasploit Rex library is provided under the 3-clause BSD license.

Copyright (c) 2005-2010, Rapid7 LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this 
   list of conditions and the following disclaimer.
   
 * Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.
   
 * Neither the name of Rapid7 LLC nor the names of its contributors may be 
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

# Generic classes
require 'rex/constants'
require 'rex/exceptions'

module Rex
	# Generic modules
	autoload :FileUtils,    'rex/file'
	autoload :Find,         'rex/file'
	autoload :Quickfile,    'rex/file'
	autoload :Text,         'rex/text'
	autoload :Job,          'rex/job_container'
	autoload :JobContainer, 'rex/job_container'
	autoload :Transformer,  'rex/transformer'
	autoload :ExtTime,      'rex/time'

	# Thread safety and synchronization
	autoload :ReadWriteLock, 'rex/sync/read_write_lock'
	autoload :ThreadSafe,    'rex/sync/thread_safe'
	autoload :Ref,           'rex/sync/ref'
	autoload :Sync,          'rex/sync/event'

	# Thread factory
	autoload :ThreadFactory, 'rex/thread_factory'

	# Encoding
	autoload :Encoder,  'rex/encoder'
	autoload :Encoders, 'rex/encoders'
	autoload :Encoding, 'rex/encoding'

	# Architecture subsystem
	autoload :Arch, 'rex/arch'

	# Assembly
	autoload :Assembly, 'rex/assembly/nasm'

	# Logging
	autoload :Logging, 'rex/logging'

	# IO
	autoload :IO, 'rex/io'

	# Sockets
	autoload :Socket, 'rex/socket'

	# Platforms
	autoload :Platforms, 'rex/platforms'

	# Protocols
	autoload :Proto, 'rex/proto'

	# Service handling
	autoload :Service, 'rex/service'

	# Parsers
	autoload :Parser, 'rex/parser'

	# Compatibility
	autoload :Compat, 'rex/compat'
end


# Overload the Kernel.sleep() function to be thread-safe
Kernel.class_eval("
	def sleep(seconds)
		Rex::ThreadSafe.sleep(seconds)
	end
")

# Overload the Kernel.select function to be thread-safe
Kernel.class_eval("
	def select(rfd = nil, wfd = nil, efd = nil, to = nil)
		Rex::ThreadSafe.select(rfd, wfd, efd, to)
	end
")
