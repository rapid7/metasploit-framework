# -*- coding: binary -*-

module Rex
module Post

##
#
# Base IO class that is modeled after the ruby IO class.
#
##
class IO
  protected
    attr_accessor :filed, :mode
  public

  ##
  #
  # Conditionals
  #
  ##

  def eof?
    return eof
  end

  def closed?
    raise NotImplementedError
  end

  def tty?
    return isatty
  end

  ##
  #
  # I/O operations
  #
  ##

  def binmode
    raise NotImplementedError
  end

  def close
    raise NotImplementedError
  end

  def close_read
    raise NotImplementedError
  end

  def close_write
    raise NotImplementedError
  end

  def each(sep = $/, &block)
    raise NotImplementedError
  end

  def each_line(sep = $/, &block)
    raise NotImplementedError
  end

  def each_byte(&block)
    raise NotImplementedError
  end

  def eof
    raise NotImplementedError
  end

  def fcntl(cmd, arg)
    raise NotImplementedError
  end

  def flush
    raise NotImplementedError
  end

  def fsync
    raise NotImplementedError
  end

  def getc
    raise NotImplementedError
  end

  def gets(sep = $/)
    raise NotImplementedError
  end

  def ioctl(cmd, arg)
    raise NotImplementedError
  end

  def isatty
    raise NotImplementedError
  end

  def lineno
    raise NotImplementedError
  end

  def pos
    raise NotImplementedError
  end

  def print
    raise NotImplementedError
  end

  def printf(fmt, *args)
    raise NotImplementedError
  end

  def putc(obj)
    raise NotImplementedError
  end

  def puts(obj)
    raise NotImplementedError
  end

  def read(length = nil, buffer = nil)
    raise NotImplementedError
  end

  def readchar
    raise NotImplementedError
  end

  def readline(sep = $/)
    raise NotImplementedError
  end

  def readlines(sep = $/)
    raise NotImplementedError
  end

  def rewind
    raise NotImplementedError
  end

  def seek(offset, whence = SEEK_SET)
    raise NotImplementedError
  end

  def stat
    raise NotImplementedError
  end

  def sync
    raise NotImplementedError
  end

  def sysread(length)
    raise NotImplementedError
  end

  def sysseek(offset, whence = SEEK_SET)
    raise NotImplementedError
  end

  def syswrite(buf)
    raise NotImplementedError
  end

  def tell
    return pos
  end

  def ungetc(val)
    raise NotImplementedError
  end

  def write(buf)
    raise NotImplementedError
  end

end

end; end # Post/Rex
