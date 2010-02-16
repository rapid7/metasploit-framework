require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net; module SSH

  # This module is used to extend sockets and other IO objects, to allow
  # them to be buffered for both read and write. This abstraction makes it
  # quite easy to write a select-based event loop
  # (see Net::SSH::Connection::Session#listen_to).
  #
  # The general idea is that instead of calling #read directly on an IO that
  # has been extended with this module, you call #fill (to add pending input
  # to the internal read buffer), and then #read_available (to read from that
  # buffer). Likewise, you don't call #write directly, you call #enqueue to
  # add data to the write buffer, and then #send_pending or #wait_for_pending_sends
  # to actually send the data across the wire.
  #
  # In this way you can easily use the object as an argument to IO.select,
  # calling #fill when it is available for read, or #send_pending when it is
  # available for write, and then call #enqueue and #read_available during
  # the idle times.
  #
  #   socket = TCPSocket.new(address, port)
  #   socket.extend(Net::SSH::BufferedIo)
  #
  #   ssh.listen_to(socket)
  #
  #   ssh.loop do
  #     if socket.available > 0
  #       puts socket.read_available
  #       socket.enqueue("response\n")
  #     end
  #   end
  #
  # Note that this module must be used to extend an instance, and should not
  # be included in a class. If you do want to use it via an include, then you
  # must make sure to invoke the private #initialize_buffered_io method in
  # your class' #initialize method:
  #
  #   class Foo < IO
  #     include Net::SSH::BufferedIo
  #
  #     def initialize
  #       initialize_buffered_io
  #       # ...
  #     end
  #   end
  module BufferedIo
    include Loggable

    # Called when the #extend is called on an object, with this module as the
    # argument. It ensures that the modules instance variables are all properly
    # initialized.
    def self.extended(object) #:nodoc:
      # need to use __send__ because #send is overridden in Socket
      object.__send__(:initialize_buffered_io)
    end

    # Tries to read up to +n+ bytes of data from the remote end, and appends
    # the data to the input buffer. It returns the number of bytes read, or 0
    # if no data was available to be read.
    def fill(n=8192)
      input.consume!
      data = recv(n)
      debug { "read #{data.length} bytes" }
      input.append(data)
      return data.length
    end

    # Read up to +length+ bytes from the input buffer. If +length+ is nil,
    # all available data is read from the buffer. (See #available.)
    def read_available(length=nil)
      input.read(length || available)
    end

    # Returns the number of bytes available to be read from the input buffer.
    # (See #read_available.)
    def available
      input.available
    end

    # Enqueues data in the output buffer, to be written when #send_pending
    # is called. Note that the data is _not_ sent immediately by this method!
    def enqueue(data)
      output.append(data)
    end

    # Returns +true+ if there is data waiting in the output buffer, and
    # +false+ otherwise.
    def pending_write?
      output.length > 0
    end

    # Sends as much of the pending output as possible. Returns +true+ if any
    # data was sent, and +false+ otherwise.
    def send_pending
      if output.length > 0
        sent = send(output.to_s, 0)
        debug { "sent #{sent} bytes" }
        output.consume!(sent)
        return sent > 0
      else
        return false
      end
    end

    # Calls #send_pending repeatedly, if necessary, blocking until the output
    # buffer is empty.
    def wait_for_pending_sends
      send_pending
      while output.length > 0
        result = IO.select(nil, [self]) or next
        next unless result[1].any?
        send_pending
      end
    end

    public # these methods are primarily for use in tests

      def write_buffer #:nodoc:
        output.to_s
      end

      def read_buffer #:nodoc:
        input.to_s
      end

    private

      #--
      # Can't use attr_reader here (after +private+) without incurring the
      # wrath of "ruby -w". We hates it.
      #++

      def input; @input; end
      def output; @output; end

      # Initializes the intput and output buffers for this object. This method
      # is called automatically when the module is mixed into an object via
      # Object#extend (see Net::SSH::BufferedIo.extended), but must be called
      # explicitly in the +initialize+ method of any class that uses
      # Module#include to add this module.
      def initialize_buffered_io
        @input = Net::SSH::Buffer.new
        @output = Net::SSH::Buffer.new
      end
  end

end; end