require 'eventmachine'
require 'test/unit'
require 'rbconfig'
require 'socket'

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

  def exception_class
    jruby? ? NativeException : RuntimeError
  end

  module PlatformHelper
    # http://blog.emptyway.com/2009/11/03/proper-way-to-detect-windows-platform-in-ruby/
    def windows?
      RbConfig::CONFIG['host_os'] =~ /mswin|mingw/
    end

    # http://stackoverflow.com/questions/1342535/how-can-i-tell-if-im-running-from-jruby-vs-ruby/1685970#1685970
    def jruby?
      defined? JRUBY_VERSION
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
end
