require 'em/pure_ruby' if ENV['EM_PURE_RUBY']
require 'eventmachine'
require 'test/unit'
require 'rbconfig'
require 'socket'

puts "EM Library Type: #{EM.library_type}"

class Test::Unit::TestCase
  class EMTestTimeout < StandardError ; end

  def setup_timeout(timeout = TIMEOUT_INTERVAL)
    EM.schedule {
      EM.add_timer(timeout) {
        raise EMTestTimeout, "Test was cancelled after #{timeout} seconds."
      }
    }
  end

  def port_in_use?(port, host="127.0.0.1")
    s = TCPSocket.new(host, port)
    s.close
    s
  rescue Errno::ECONNREFUSED
    false
  end

  def next_port
    @@port ||= 9000
    begin
      @@port += 1
    end while port_in_use?(@@port)

    @@port
  end

  # Returns true if the host have a localhost 127.0.0.1 IPv4.
  def self.local_ipv4?
    return @@has_local_ipv4 if defined?(@@has_local_ipv4)
    begin
      get_my_ipv4_address "127.0.0.1"
      @@has_local_ipv4 = true
    rescue
      @@has_local_ipv4 = false
    end
  end

  # Returns true if the host have a public IPv4 and stores it in
  # @@public_ipv4.
  def self.public_ipv4?
    return @@has_public_ipv4 if defined?(@@has_public_ipv4)
    begin
      @@public_ipv4 = get_my_ipv4_address "1.2.3.4"
      @@has_public_ipv4 = true
    rescue
      @@has_public_ipv4 = false
    end
  end

  # Returns true if the host have a localhost ::1 IPv6.
  def self.local_ipv6?
    return @@has_local_ipv6 if defined?(@@has_local_ipv6)
    begin
      get_my_ipv6_address "::1"
      @@has_local_ipv6 = true
    rescue
      @@has_local_ipv6 = false
    end
  end

  # Returns true if the host have a public IPv6 and stores it in
  # @@public_ipv6.
  def self.public_ipv6?
    return @@has_public_ipv6 if defined?(@@has_public_ipv6)
    begin
      @@public_ipv6 = get_my_ipv6_address "2001::1"
      @@has_public_ipv6 = true
    rescue
      @@has_public_ipv6 = false
    end
  end

  # Returns an array with the localhost addresses (IPv4 and/or IPv6).
  def local_ips
    return @@local_ips if defined?(@@local_ips)
    @@local_ips = []
    @@local_ips << "127.0.0.1" if self.class.local_ipv4?
    @@local_ips << "::1" if self.class.local_ipv6?
    @@local_ips
  end

  def exception_class
    jruby? ? NativeException : RuntimeError
  end

  module PlatformHelper
    # http://blog.emptyway.com/2009/11/03/proper-way-to-detect-windows-platform-in-ruby/
    def windows?
      RbConfig::CONFIG['host_os'] =~ /mswin|mingw/
    end

    def solaris?
      RUBY_PLATFORM =~ /solaris/
    end

    # http://stackoverflow.com/questions/1342535/how-can-i-tell-if-im-running-from-jruby-vs-ruby/1685970#1685970
    def jruby?
      defined? JRUBY_VERSION
    end

    def rbx?
      defined?(RUBY_ENGINE) && RUBY_ENGINE == 'rbx'
    end
  end

  include PlatformHelper
  extend PlatformHelper

  # Tests run significantly slower on windows. YMMV
  TIMEOUT_INTERVAL = windows? ? 1 : 0.25

  def silent
    backup, $VERBOSE = $VERBOSE, nil
    begin
      yield
    ensure
      $VERBOSE = backup
    end
  end


  private

  def self.get_my_ipv4_address ip
    orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily
    UDPSocket.open(Socket::AF_INET) do |s|
      s.connect ip, 1
      s.addr.last
    end
  ensure
    Socket.do_not_reverse_lookup = orig
  end

  def self.get_my_ipv6_address ip
    orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily
    UDPSocket.open(Socket::AF_INET6) do |s|
      s.connect ip, 1
      s.addr.last
    end
  ensure
    Socket.do_not_reverse_lookup = orig
  end

end
