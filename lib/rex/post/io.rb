# -*- coding: binary -*-
module Rex
module Post

##
# Base IO class that is modeled after the ruby IO class.
#
# This is an abstract base class that defines the interface for
# post-exploitation I/O operations. Subclasses must implement
# the actual I/O functionality.
##
class IO
  protected
    attr_accessor :filed, :mode
  public

  ##
  # Conditionals
  ##

  # Checks if the end of file has been reached.
  #
  # @return [Boolean] true if at end of file
  def eof?
    return eof
  end

  # Checks if the I/O stream is closed.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Boolean] true if stream is closed
  def closed?
    raise NotImplementedError
  end

  # Checks if the I/O stream is a terminal device.
  #
  # @return [Boolean] true if stream is a TTY
  def tty?
    return isatty
  end

  ##
  # I/O operations
  ##

  # Sets the stream to binary mode.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [IO] self
  def binmode
    raise NotImplementedError
  end

  # Closes the I/O stream.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [nil]
  def close
    raise NotImplementedError
  end

  # Closes the read end of a duplex I/O stream.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [nil]
  def close_read
    raise NotImplementedError
  end

  # Closes the write end of a duplex I/O stream.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [nil]
  def close_write
    raise NotImplementedError
  end

  # Iterates over each line in the stream.
  #
  # @param sep [String] line separator (default: $/)
  # @yield [String] each line from the stream
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [void]
  def each(sep = $/, &block)
    raise NotImplementedError
  end

  # Alias for {#each}.
  #
  # @param sep [String] line separator (default: $/)
  # @yield [String] each line from the stream
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [void]
  def each_line(sep = $/, &block)
    raise NotImplementedError
  end

  # Iterates over each byte in the stream.
  #
  # @yield [Integer] each byte from the stream
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [void]
  def each_byte(&block)
    raise NotImplementedError
  end

  # Checks if end of file has been reached.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Boolean] true if at end of file
  def eof
    raise NotImplementedError
  end

  # Performs low-level file control operation.
  #
  # @param cmd [Integer] control command
  # @param arg [Integer, String] command argument
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] result of operation
  def fcntl(cmd, arg)
    raise NotImplementedError
  end

  # Flushes buffered data to the underlying I/O stream.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [IO] self
  def flush
    raise NotImplementedError
  end

  # Synchronizes all buffered data with the storage device.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [0] zero on success
  def fsync
    raise NotImplementedError
  end

  # Reads a single character from the stream.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer, nil] character code or nil at EOF
  def getc
    raise NotImplementedError
  end

  # Reads the next line from the stream.
  #
  # @param sep [String] line separator (default: $/)
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [String, nil] next line or nil at EOF
  def gets(sep = $/)
    raise NotImplementedError
  end

  # Performs low-level I/O control operation.
  #
  # @param cmd [Integer] control command
  # @param arg [Integer, String] command argument
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] result of operation
  def ioctl(cmd, arg)
    raise NotImplementedError
  end

  # Checks if the stream is associated with a terminal device.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Boolean] true if stream is a TTY
  def isatty
    raise NotImplementedError
  end

  # Gets the current line number.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] current line number
  def lineno
    raise NotImplementedError
  end

  # Gets the current file position.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] current byte offset
  def pos
    raise NotImplementedError
  end

  # Writes a string to the stream.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] number of bytes written
  def print
    raise NotImplementedError
  end

  # Writes a formatted string to the stream.
  #
  # @param fmt [String] format string
  # @param args [Array] values to format
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [nil]
  def printf(fmt, *args)
    raise NotImplementedError
  end

  # Writes a character to the stream.
  #
  # @param obj [Integer] character code to write
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] the character code written
  def putc(obj)
    raise NotImplementedError
  end

  # Writes a string followed by newline to the stream.
  #
  # @param obj [String] data to write
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [nil]
  def puts(obj)
    raise NotImplementedError
  end

  # Reads data from the stream.
  #
  # @param length [Integer, nil] number of bytes to read (nil = read all)
  # @param buffer [String, nil] buffer to read into
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [String, nil] data read or nil at EOF
  def read(length = nil, buffer = nil)
    raise NotImplementedError
  end

  # Reads a single character as a string.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [String, nil] character or nil at EOF
  def readchar
    raise NotImplementedError
  end

  # Reads the next line from the stream.
  #
  # @param sep [String] line separator (default: $/)
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [String] next line
  # @raise [EOFError] if at end of file
  def readline(sep = $/)
    raise NotImplementedError
  end

  # Reads all lines from the stream into an array.
  #
  # @param sep [String] line separator (default: $/)
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Array<String>] array of lines
  def readlines(sep = $/)
    raise NotImplementedError
  end

  # Repositions the stream to the beginning.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [0] zero on success
  def rewind
    raise NotImplementedError
  end

  # Repositions the file pointer.
  #
  # @param offset [Integer] byte offset
  # @param whence [Integer] position reference (SEEK_SET, SEEK_CUR, SEEK_END)
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [0] zero on success
  def seek(offset, whence = SEEK_SET)
    raise NotImplementedError
  end

  # Gets file status information.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [File::Stat] file status object
  def stat
    raise NotImplementedError
  end

  # Synchronizes the stream with the underlying storage.
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [IO] self
  def sync
    raise NotImplementedError
  end

  # Reads data at the system level.
  #
  # @param length [Integer] number of bytes to read
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [String] data read
  def sysread(length)
    raise NotImplementedError
  end

  # Repositions the file pointer at the system level.
  #
  # @param offset [Integer] byte offset
  # @param whence [Integer] position reference (SEEK_SET, SEEK_CUR, SEEK_END)
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] new file offset
  def sysseek(offset, whence = SEEK_SET)
    raise NotImplementedError
  end

  # Writes data to the stream at the OS level.
  #
  # @param buf [String] data to write
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] number of bytes written
  def syswrite(buf)
    raise NotImplementedError
  end

  # Gets the current file position (alias for {#pos}).
  #
  # @return [Integer] current byte offset
  def tell
    return pos
  end

  # Pushes a character back onto the stream.
  #
  # @param val [Integer] character code to push back
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [nil]
  def ungetc(val)
    raise NotImplementedError
  end

  # Writes data to the stream.
  #
  # @param buf [String] data to write
  #
  # @raise [NotImplementedError] Must be implemented by subclass
  #
  # @return [Integer] number of bytes written
  def write(buf)
    raise NotImplementedError
  end

end

end; end # Post/Rex
