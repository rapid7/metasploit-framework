# Encoding: ASCII-8BIT

module Msf
  class Post
    module Linux
      # This mixin lets you programmatically interact with F5's "mcp" service,
      # which is a database service on a variety of F5's devices, including
      # BIG-IP and BIG-IQ.
      #
      # mcp uses a UNIX domain socket @ /var/run/mcp for all communications.
      # As of writing this module, it's world-accessible, so anybody can query
      # or write to it. We implemented a few interesting things as modules, and
      # your best bet for learning how to work this is to look at those modules,
      # but this will document it briefly.
      #
      # Data is read and written by serializing a TLV-style structure and
      # writing it to that socket, then parsing the response.
      #
      # If you're just reading data, you can use `mcp_simple_query()` to build
      # a query that fetches everything under a given name, and get a Hash of
      # data back. That's by far the easiest way to handle things.
      #
      # To create a more complex query, you'll need to use mcp_build(), which
      # serializes a message. You can generate a single message, or an array of
      # them. Then use mcp_send_recv() to write it/them to the socket.
      # Additionally, mcp_send_recv() automatically parses them and returns
      # a whole big nested array of data.
      #
      # To actually use that data without going crazy, I suggest using either
      # mcp_get_single(tagname) to fetch a single tag, or
      # mcp_get_multiple(tagname) if multiple of the same tag can be returned.
      # Finally, the response from that can be passed to mcp_to_h() to convert
      # the response to a hash (note that if there are multiple of the same tag,
      # map_to_h() will only keep one of them).
      #
      # Obviously, this is all way more complex than mcp_simple_query(). You can
      # see this in action in the module `linux/local/f5_create_user`.
      module F5Mcp # rubocop:disable Metrics/ModuleLength
        def initialize(info = {})
          file = ::File.join(Msf::Config.data_directory, 'f5-mcp-objects.txt')
          objects = ::File.read(file)

          raise("Could not load #{file}!") unless objects

          @tags_by_id =
            objects
            .split(/\n/)
            .reject { |o| o.start_with?('#') }
            .map(&:strip)
            .map do |o|
              value, tag = o.split(/ /, 2)

              raise("Invalid line in #{file}: #{o}") if tag.nil?

              [value.to_i(16), tag]
            end
            .to_h
            .freeze

          @tags_by_name = @tags_by_id.invert.freeze

          super(info)
        end

        # Parse one or more packets (including headers) into an array of
        # packets.
        def mcp_parse_responses(incoming_data)
          replies = []

          while incoming_data.length > 16
            # Grab the length and remove the header from the incoming data
            expected_length, _, incoming_data = incoming_data.unpack('Na12a*')

            # Read the packet
            packet, incoming_data = incoming_data.unpack("a#{expected_length}a*")

            # Sanity check
            if packet.length != expected_length
              print_warning('mcp message is truncated!')
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

          print_error("mcp isn't responding with a full message, giving up")
          nil
        end

        # Recursively parse an mcp message from a binary stream into an object
        #
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-parser.rb
        def mcp_parse(stream)
          # Reminder: this has to be an array, not a hash, because there are
          # often duplicate entries (like multiple userdb_entry results when a
          # query is performed).
          result = []

          # Make a Hash of parsers. Some of them are recursive, which is fun!
          #
          # They all take the stream as an input argument, and return
          # [value, stream]
          parsers = {
            # The easy stuff - simple values
            'ulong' => proc { |s| s.unpack('Na*') },
            'long' => proc { |s| s.unpack('Na*') },
            'uquad' => proc { |s| s.unpack('Q>a*') },
            'uword' => proc { |s| s.unpack('na*') },
            'byte' => proc { |s| s.unpack('Ca*') },
            'service' => proc { |s| s.unpack('na*') },

            # Parse 'time' as a time
            'time' => proc do |s|
              value, s = s.unpack('Na*')
              [Time.at(value), s]
            end,

            # Look up 'tag' values
            'tag' => proc do |s|
              value, s = s.unpack('na*')
              [@tags_by_id[value], s]
            end,

            # Parse MAC addresses
            'mac' => proc do |s|
              value, s = s.unpack('a6a*')
              [value.bytes.map { |b| '%02x'.format(b) }.join(':'), s]
            end,

            # 'string' is prefixed by two length values
            'string' => proc do |s|
              length, otherlength, s = s.unpack('Nna*')

              # I'm sure the two length values have a semantic difference, but just check for sanity
              if otherlength + 2 != length
                raise "Inconsistent string lengths: #{length} + #{otherlength}"
              end

              s.unpack("a#{otherlength}a*")
            end,

            # 'structure' is recursive
            'structure' => proc do |s|
              length, s = s.unpack('Na*')
              struct, s = s.unpack("a#{length}a*")

              [mcp_parse(struct), s]
            end,

            # 'array' is a bunch of consecutive values of the same type, which
            # means we need to index back into this same parser array
            'array' => proc do |s|
              length, s = s.unpack('Na*')
              array, s = s.unpack("a#{length}a*")

              type, elements, array = array.unpack('nNa*')
              type = @tags_by_id[type] || '<unknown type 0x%04x>'.format(type)

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

              tag = @tags_by_id[tag] || '<unknown tag 0x%04x>'.format(tag)
              type = @tags_by_id[type] || '<unknown type 0x%04x>'.format(type)

              if parsers[type]
                value, stream = parsers[type].call(stream)
                result << {
                  tag: tag,
                  value: value
                }
              else
                raise "Tried to parse unknown mcp type (skipping): type = #{type}, tag = #{tag}"
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
        def mcp_get_single(hash, name)
          # Get all the entries
          entries = mcp_get_multiple(hash, name)

          if entries.empty?
            # If there are none, return nil
            return nil
          elsif entries.length == 1
            # If there's one, return it
            return entries.pop
          else
            # If there are multiple entries, print a warning and return nil
            print_error("Query for mcp type #{name} was supposed to have one response but had #{entries.length}")
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
        def mcp_get_multiple(hash, name)
          hash.select { |entry| entry[:tag] == name }.map { |entry| entry[:value] }
        end

        # Take an array of results from an mcp query, and change them from
        # an array of tag=>value into a hash.
        #
        # Note! If there are multiple fields with the same tag, this will
        # only return one of them!
        def mcp_to_h(array)
          array.map do |r|
            [r[:tag], r[:value]]
          end.to_h
        end

        # Build an mcp message
        #
        # Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-builder.rb
        def mcp_build(tag, type, data)
          if @tags_by_name[tag].nil?
            raise "Invalid mcp tag: #{tag}"
          end
          if @tags_by_name[type].nil?
            raise "Invalid mcp type: #{type}"
          end

          out = ''
          if type == 'structure'
            out = [data.join.length, data.join].pack('Na*')
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
            raise "Unknown type: #{type}"
          end

          out = [@tags_by_name[tag], @tags_by_name[type], out].pack('nna*')

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
            print_error('mcp_send_recv failed')
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
