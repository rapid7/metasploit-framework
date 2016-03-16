# -*- coding: binary -*-
#
# Provides some sanity checks against the ruby build and version
#

# Check for ruby 1.x and throw a warning
if (RUBY_VERSION =~ /^1/)
  $stderr.puts "*** Ruby 1.x is not supported, please upgrade to Ruby 2.1 or newer."
  exit(0)
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
