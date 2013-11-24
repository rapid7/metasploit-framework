# -*- coding: binary -*-

module Rex

###
#
# Base mixin for all exceptions that can be thrown from inside Rex.
#
###
module Exception
end

###
#
# This exception is raised when a timeout occurs.
#
###
class TimeoutError < Interrupt
  include Exception

  def to_s
    "Operation timed out."
  end
end

###
#
# This exception is raised when a method is called or a feature is used that
# is not implemented.
#
###
class NotImplementedError < ::NotImplementedError
  include Exception

  def to_s
    "The requested method is not implemented."
  end
end

###
#
# This exception is raised when a generalized runtime error occurs.
#
###
class RuntimeError < ::RuntimeError
  include Exception
end

###
#
# This exception is raised when an invalid argument is supplied to a method.
#
###
class ArgumentError < ::ArgumentError
  include Exception

  def initialize(message = nil)
    @message = message
  end

  def to_s
    str = 'An invalid argument was specified.'
    if @message
      str << " #{@message}"
    end
    str
  end
end

###
#
# This exception is raised when an argument that was supplied to a method
# could not be parsed correctly.
#
###
class ArgumentParseError < ::ArgumentError
  include Exception

  def to_s
    "The argument could not be parsed correctly."
  end
end

###
#
# This exception is raised when an argument is ambiguous.
#
###
class AmbiguousArgumentError < ::RuntimeError
  include Exception

  def initialize(name = nil)
    @name = name
  end

  def to_s
    "The name #{@name} is ambiguous."
  end
end

###
#
# This error is thrown when a stream is detected as being closed.
#
###
class StreamClosedError < ::IOError
  include Exception

  def initialize(stream)
    @stream = stream
  end

  def stream
    @stream
  end

  def to_s
    "Stream #{@stream} is closed."
  end
end

##
#
# Socket exceptions
#
##

###
#
# This exception is raised when a general socket error occurs.
#
###
module SocketError
  include Exception

  def to_s
    "A socket error occurred."
  end
end

###
#
# This exception is raised when there is some kind of error related to
# communication with a host.
#
###
module HostCommunicationError
  def initialize(addr = nil, port = nil)
    self.host = addr
    self.port = port
  end

  #
  # This method returns a printable address and optional port associated
  # with the host that triggered the exception.
  #
  def addr_to_s
    if host and port
      "(#{host}:#{port})"
    elsif host
      "(#{host})"
    else
      ""
    end
  end

  attr_accessor :host, :port
end


###
#
# This is a generic exception for errors that cause a connection to fail.
#
###
class ConnectionError < ::IOError
  include SocketError
  include HostCommunicationError
end

###
#
# This exception is raised when a connection attempt fails because the remote
# side refused the connection.
#
###
class ConnectionRefused < ConnectionError
  def to_s
    "The connection was refused by the remote host #{addr_to_s}."
  end
end

###
#
# This exception is raised when a connection attempt fails because the remote
# side is unreachable.
#
###
class HostUnreachable < ConnectionError
  def to_s
    "The host #{addr_to_s} was unreachable."
  end
end

###
#
# This exception is raised when a connection attempt times out.
#
###
class ConnectionTimeout < ConnectionError
  def to_s
    "The connection timed out #{addr_to_s}."
  end
end


###
#
# This exception is raised when an attempt to use an address or port that is
# already in use occurs, such as binding to a host on a given port that is
# already in use.  Note that Windows raises this in some cases when attempting
# to connect to addresses that it can't handle, e.g. "0.0.0.0".  Thus, this is
# a ConnectionError.
#
###
class AddressInUse < ConnectionError
  include SocketError
  include HostCommunicationError

  def to_s
    "The address is already in use #{addr_to_s}."
  end
end

###
#
# This exception is raised when an unsupported internet protocol is specified.
#
###
class UnsupportedProtocol < ::ArgumentError
  include SocketError

  def initialize(proto = nil)
    self.proto = proto
  end

  def to_s
    "The protocol #{proto} is not supported."
  end

  attr_accessor :proto
end


###
#
# This exception is raised when a proxy fails to pass a connection
#
###
class ConnectionProxyError < ConnectionError
  def initialize(host,port,ptype,reason)
    super(host,port)
    self.ptype = ptype
    self.reason = reason
  end

  def to_s
    self.ptype + ": " + self.reason
  end

  attr_accessor :ptype, :reason
end

end

