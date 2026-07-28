# -*- coding: binary -*-

module Rex
  Root = File.join(File.expand_path(File.dirname(__FILE__)), 'rex')
  LogSource = "rex"

  # library for creating Powershell scripts for exploitation purposes
  autoload :Powershell, 'rex/powershell'
  # Library for working with OLE
  autoload :OLE, 'rex/ole'
  # Library for creating and/or parsing MIME messages
  autoload :MIME, 'rex/mime'
  # Exploit Helper Library
  autoload :Exploitation, 'rex/exploitation'
  # Binary parsing tools (PE, ELF, Mach-O)
  autoload :BinTools, 'rex/bin_tools'
  autoload :PeParsey, 'rex/peparsey'
  autoload :PeScan, 'rex/pescan'
  autoload :ElfParsey, 'rex/elfparsey'
  autoload :ElfScan, 'rex/elfscan'
  autoload :MachParsey, 'rex/machparsey'
  autoload :MachScan, 'rex/machscan'
  autoload :ImageSource, 'rex/image_source'
  # SSLScan
  autoload :SSLScan, 'rex/sslscan/scanner'
end

#
# REX Gems
#

# Text manipulation library for things like generating random string
require 'rex/text'
# Library for Generating Randomized strings valid as Identifiers such as variable names
require 'rex/random_identifier'
# Library for processing and creating Zip compatible archives
require 'rex/zip'
# Library for parsing offline Windows Registry files
require 'rex/registry'
# Library for parsing Java serialized streams
require 'rex/java'
# Library for creating C-style Structs
require 'rex/struct2'
# Library for polymorphic encoders
require 'rex/encoder'
# Architecture subsystem
require 'rex/arch'

# Generic classes
require 'rex/file'

# Thread safety and synchronization
require 'rex/sync'

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

# Compatibility
require 'rex/compat'

# Versions
require 'rex/version'

# Overload the Kernel.sleep() function to be thread-safe
Kernel.class_eval(<<-EOF, __FILE__, __LINE__ + 1)
  def sleep(seconds=nil)
    Rex::ThreadSafe.sleep(seconds)
  end
EOF

# Overload the Kernel.select function to be thread-safe
Kernel.class_eval(<<-EOF, __FILE__, __LINE__ + 1)
  def select(rfd = nil, wfd = nil, efd = nil, to = nil)
    Rex::ThreadSafe.select(rfd, wfd, efd, to)
  end
EOF

# Add the deprecated File.exists? method to call non-deprecated File.exist?
File.class_eval(<<-EOF, __FILE__, __LINE__ + 1)
  def File.exists?(fname)
    File.exist?(fname)
  end
EOF
