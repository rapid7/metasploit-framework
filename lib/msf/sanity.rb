# -*- coding: binary -*-
#
# Provides some sanity checks against the ruby build and version
#

# Check for the broken pack/unpack in OS X 10.4.x
if ([1].pack('n') == "\x01\x00")
  $stderr.puts "*** This ruby build has a broken pack/unpack implementation! "

  if (RUBY_PLATFORM =~ /darwin/)
    $stderr.puts "    Apple shipped a broken version of ruby with the 10.4.x   "
    $stderr.puts "    release. Please install ruby from source, or use one of  "
    $stderr.puts "    the free package managers to obtain a working ruby build."
  end

  exit(0)
end

# Check for ruby 1.8.2 as the minimal supported version
if (RUBY_VERSION =~ /^1\.[0-7]\./ or RUBY_VERSION =~ /^1\.8\.[0-1]$/)
  $stderr.puts "*** This version of ruby is not supported, please upgrade to 1.8.7+"
  exit(0)
end

# Check for ruby 1.9.0 and throw a big nasty warning
if (RUBY_VERSION =~ /^1\.9\.0/)
  $stderr.puts "*** Ruby 1.9.0 is not supported, please upgrade to Ruby 1.9.3 or newer."
  exit(0)
end

# Check for ruby 1.9.1 and throw a warning
if (RUBY_VERSION =~ /^1\.9\.1/)
  $stderr.puts "*** Ruby 1.9.1 is not supported, please upgrade to Ruby 1.9.3 or newer."
end

if(RUBY_VERSION =~ /^(1\.9|2\.0)\./)
  # Load rubygems before changing default_internal, otherwise we may get
  # Encoding::UndefinedConversionError as the gemspec files are loaded
  require 'rubygems'
  Gem::Version # trigger Rubygems to fully load

  # Force binary encoding for Ruby versions that support it
  if(Object.const_defined?('Encoding') and Encoding.respond_to?('default_external='))
    Encoding.default_external = Encoding.default_internal = "binary"
  end
end

if(RUBY_PLATFORM == 'java')
  require 'socket'
  s = Socket.new(::Socket::AF_INET, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_TCP)
  if(not s.respond_to?('bind'))
    $stderr.puts "*** JRuby 1.5.0+ is required to use Metasploit with jRuby"
    exit(0)
  end

  $stderr.puts "*** Warning: JRuby support is still incomplete, few things will work properly!"
  trap Signal::list['INT'] do
    Thread.main.raise Interrupt.new
  end

  s.close
end

# Check for OpenSSL and print a warning if it is not installed
begin
  require 'openssl'
rescue ::LoadError
  $stderr.puts "*** The ruby-openssl library is not installed, many features will be disabled!"
  $stderr.puts "*** Examples: Meterpreter, SSL Sockets, SMB/NTLM Authentication, and more"
end


#
# Check for the ugly 1.8.7 short-named constants bug
#

class ConstBugTestA
  Const = 'A'
  def test
    Const == 'A'
  end
end

ConstBugTestC = ConstBugTestA.dup

class ConstBugTestB < ConstBugTestC
  Const = 'B'
end

def ruby_187_const_bug
  bugged = false

  begin
    ConstBugTestA.new.test()
    ConstBugTestB.new.test()
  rescue ::NameError
    bugged = true
  end

  bugged
end

if(ruby_187_const_bug())
  $stderr.puts ""
  $stderr.puts "***********************************************************************"
  $stderr.puts "***                                                                   *"
  $stderr.puts "*** This version of the Ruby interpreter contains a serious bug       *"
  $stderr.puts "*** related to short-named constants, we strongly recommend that you  *"
  $stderr.puts "*** switch to a fixed version. Unfortunately, some Linux distros have *"
  $stderr.puts "*** backported the buggy patch into 1.8.6, so you may need to contact *"
  $stderr.puts "*** your vendor and ask them to review the URL below.                 *"
  $stderr.puts "***                                                                   *"
  $stderr.puts "*** Alternatively, you can download, build, and install the latest    *"
  $stderr.puts "*** stable snapshot of Ruby from the following URL:                   *"
  $stderr.puts "***  - http://www.ruby-lang.org/                                      *"
  $stderr.puts "***                                                                   *"
  $stderr.puts "*** For more information, please see the following URL:               *"
  $stderr.puts "***  - https://bugs.launchpad.net/bugs/282302                         *"
  $stderr.puts "***                                                                   *"
  $stderr.puts "***********************************************************************"
  $stderr.puts ""
end

