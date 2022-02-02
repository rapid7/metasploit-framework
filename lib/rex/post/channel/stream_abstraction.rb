# -*- coding: binary -*-

require 'rex/io/stream_abstraction'

module Rex
  module Post
    module Channel
      module StreamAbstraction
        include Rex::IO::StreamAbstraction

        #
        # Read *length* bytes from the channel. If the operation times out, the data
        # that was read will be returned or nil if no data was read.
        #
        def read(length = nil)
          if closed?
            raise IOError, 'Channel has been closed.', caller
          end

          buf = ''
          length = 65536 if length.nil?

          begin
            buf << lsock.recv(length - buf.length) while buf.length < length
          rescue StandardError
            buf = nil if buf.empty?
          end

          buf
        end
      end
    end
  end
end
