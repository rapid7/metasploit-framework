module RubySMB
  class Client    # This module holds all of the methods backing the {RubySMB::Client#open_file} method
    module Utils

      attr_accessor :tree_connects
      attr_accessor :open_files

      attr_accessor :use_ntlmv2, :usentlm2_session, :send_lm, :use_lanman_key, :send_ntlm, :spnopt
      attr_accessor :evasion_opts

      attr_accessor :native_os, :native_lm, :verify_signature, :auth_user

      attr_accessor :last_file_id

      def last_tree
        @tree_connects.last
      end

      def last_file
        @open_files[@last_file_id]
      end

      def last_tree_id
        last_tree.id
      end

      def open(path, disposition=RubySMB::Dispositions::FILE_OPEN, write: false, read: true)
         file = last_tree.open_file(filename: path.sub(/^\\/, ''), write: write, read: read, disposition: disposition)
         @last_file_id = if file.respond_to?(:guid)
           file.guid.to_binary_s
         elsif file.respond_to?(:fid)
           file.fid.to_binary_s
         end
         @open_files[@last_file_id] = file
         @last_file_id
      end

      def create_pipe(path, disposition=RubySMB::Dispositions::FILE_OPEN_IF)
        open(path.gsub(/\\/, ''), disposition, write: true, read: true)
      end

      #Writes data to an open file handle
      def write(file_id, offset = 0, data = '', do_recv = true)
        @open_files[file_id].send_recv_write(data: data, offset: offset)
      end

      def read(file_id, offset = 0, length = last_file.size)
        data = @open_files[file_id].send_recv_read(read_length: length, offset: offset)
        data.bytes
      end

      def delete(path)
        file = last_tree.open_file(filename: path.sub(/^\\/, ''), delete: true)
        file.delete
        file.close
      end

      def close(file_id, tree_id)
       @open_files[file_id].close
      end

      def tree_disconnect(share)
       @tree_connects.detect{|tree| tree.id == share }.disconnect!
      end

      def native_os
        @peer_native
      end

      def native_lm
        @native_lm
      end

      def verify_signature
        @signing_required
      end

      def auth_user
        @username
      end

    end
  end
end
