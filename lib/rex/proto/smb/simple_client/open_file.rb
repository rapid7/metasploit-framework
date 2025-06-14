# -*- coding: binary -*-
module Rex::Proto::SMB
  class SimpleClient
    #
    # This represents an open file, which can be read, written, or closed
    #
    class OpenFile
      attr_accessor :name, :tree_id, :file_id, :mode, :client, :chunk_size, :versions

      def initialize(client, name, tree_id, file_id, versions)
        self.client = client
        self.name = name
        self.tree_id = tree_id
        self.file_id = file_id
        self.chunk_size = 48000
        self.versions = versions
      end

      def delete
        begin
          close
        rescue StandardError
        end
        client.delete(name, tree_id)
      end

      # Close this open file
      def close
        client.close(file_id, tree_id)
      end

      def read_ruby_smb(length, offset, depth = 0)
        file_size = client.open_files[client.last_file_id].size
        file_size_remaining = file_size - offset
        if length.nil?
          max_size = file_size_remaining
        else
          max_size = [length, file_size_remaining].min
        end

        fptr = offset
        chunk = [max_size, chunk_size].min

        data = client.read(file_id, fptr, chunk).pack('C*')
        fptr += data.length

        while data.length < max_size
          if (max_size - data.length) < chunk
            chunk = max_size - data.length
          end
          new_data = client.read(file_id, fptr, chunk).pack('C*')
          data << new_data
          fptr += new_data.length
        end

        data
      rescue RubySMB::Error::UnexpectedStatusCode => e
        if e.message == 'STATUS_PIPE_EMPTY' && depth < 20
          read_ruby_smb(max_size, offset, depth + 1)
        else
          raise e
        end
      end

      def read_rex_smb(length, offset)
        if length.nil?
          data = ''
          fptr = offset
          ok = client.read(file_id, fptr, chunk_size)
          while ok && ok['Payload'].v['DataLenLow'] > 0
            buff = ok.to_s.slice(
              ok['Payload'].v['DataOffset'] + 4,
              ok['Payload'].v['DataLenLow']
            )
            data << buff
            break if ok['Payload'].v['Remaining'] == 0
            fptr += ok['Payload'].v['DataLenLow']

            begin
              ok = client.read(file_id, fptr, chunk_size)
            rescue XCEPT::ErrorCode => e
              case e.error_code
              when 0x00050001
                # Novell fires off an access denied error on EOF
                ok = nil
              else
                raise e
              end
            end
          end
        else
          ok = client.read(file_id, offset, length)
          data = ok.to_s.slice(
            ok['Payload'].v['DataOffset'] + 4,
            ok['Payload'].v['DataLenLow']
          )
        end
        data
      end

      # Read data from the file
      def read(length = nil, offset = 0)
        if self.client.is_a?(RubySMB::Client)
          read_ruby_smb(length, offset)
        else
          read_rex_smb(length, offset)
        end
      end

      def <<(data)
        write(data)
      end

      # Write data to the file
      def write(data, offset = 0)
        # Track our offset into the remote file
        fptr = offset

        # Duplicate the data so we can use slice!
        data = data.dup

        # Take our first chunk of bytes
        chunk = data.slice!(0, chunk_size)

        # Keep writing data until we run out
        until chunk.empty?
          ok = client.write(file_id, fptr, chunk)
          if self.client.is_a?(RubySMB::Client)
            cl = ok
          else
            cl = ok['Payload'].v['CountLow']
          end

          # Partial write, push the failed data back into the queue
          if cl != chunk.length
            data = chunk.slice(cl - 1, chunk.length - cl) + data
          end

          # Increment our painter and grab the next chunk
          fptr += cl
          chunk = data.slice!(0, chunk_size)
        end
        fptr
      end
    end
  end
end
