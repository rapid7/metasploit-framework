# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/bofloader/tlv'
require 'rex/post/meterpreter/extensions/bofloader/command_ids'
require 'rex/post/meterpreter/extensions/bofloader/cna_argument_parser'
require 'rex/post/meterpreter/extensions/bofloader/cna_parser'
require 'rexml/document'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Bofloader
          ###
          #
          # Bofloader extension - Executes a beacon object file in
          # the current meterpreter session.
          #
          # Kevin Haubris (@kev169)
          # Kevin Clark (@GuhnooPlusLinux)
          # TrustedSec (@TrustedSec)
          #
          ###

          class BofPackingError < RuntimeError
          end

          # Code referenced from: https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
          # Emulates the native Cobalt Strike bof_pack() function.
          # Documented here: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
          #
          # Type      Description                             Unpack With (C)
          # --------|---------------------------------------|------------------------------
          # b       | binary data                           | BeaconDataExtract
          # i       | 4-byte integer                        | BeaconDataInt
          # s       | 2-byte short integer                  | BeaconDataShort
          # z       | zero-terminated+encoded string        | BeaconDataExtract
          # Z       | zero-terminated wide-char string      | (wchar_t *)BeaconDataExtract
          class BofPack
            def initialize
              reset
            end

            def add_binary(binary)
              # Add binary data to the buffer
              binary = binary.bytes if binary.is_a? String
              b_length = binary.length
              binary = [b_length] + binary
              buf = binary.pack("I<c#{b_length}")
              @size += buf.length
              @buffer << buf
            end

            def add_int(dint)
              @buffer << [dint.to_i].pack('I<')
              @size += 4
            end

            def add_short(short)
              @buffer << [short.to_i].pack('s<')
              @size += 2
            end

            def add_str(str)
              str = str.encode('utf-8').bytes
              str << 0x00 # Null terminated strings...
              s_length = str.length
              str = [s_length] + str
              buf = str.pack("I<c#{s_length}")
              @size += buf.length
              @buffer << buf
            end

            def add_wstr(wstr)
              wstr = wstr.encode('utf-16le').bytes
              wstr << 0x00 << 0x00 # Null terminated wide string
              s_length = wstr.length
              wstr = [s_length] + wstr
              buf = wstr.pack("I<c#{s_length}")
              @size += buf.length
              @buffer << buf
            end

            def finalize_buffer
              output = [@size].pack('I<') + @buffer
              reset
              output
            end

            def reset
              @buffer = ''
              @size = 0
            end

            def bof_pack(fstring, args)
              # Wrapper function to pack an entire bof command line into a buffer
              if fstring.nil? || args.nil?
                return finalize_buffer
              end

              if fstring.length != args.length
                raise BofPackingError, 'Mismatched format and argument lengths'
              end

              fstring.chars.zip(args).each do |c, arg|
                case c
                when 'b'
                  add_binary(arg)
                when 'i'
                  add_int(arg)
                when 's'
                  add_short(arg)
                when 'z'
                  add_str(arg)
                when 'Z'
                  add_wstr(arg)
                else
                  raise BofPackingError, "Invalid character in format string: #{c}. Must be one of \"b, i, s, z, Z\""
                end
              end

              # return the packed bof_string
              finalize_buffer
            end
          end

          # Beacon object file (BOF) loader
          class Bofloader < Extension

            def self.extension_id
              EXTENSION_ID_BOFLOADER
            end

            # Typical extension initialization routine.
            #
            # @param client (see Extension#initialize)
            def initialize(client)
              super(client, 'bofloader')
              @cna_catalog = { 'path' => nil, 'bofs' => {}, 'warnings' => [] }

              client.register_extension_aliases(
                [
                  {
                    'name' => 'bofloader',
                    'ext' => self
                  },
                ]
              )
            end

            # Returns the CNA catalog loaded in this Meterpreter session.
            #
            # @return [Hash] Loaded script path, BOF definitions, and warnings.
            attr_reader :cna_catalog

            # Loads compatible BOF aliases from an Aggressor script.
            #
            # @param path [String] Local CNA script path.
            # @return [Hash] The new CNA catalog.
            def load_cna(path)
              catalog = CnaParser.parse(path: ::File.expand_path(path))
              @cna_catalog = catalog
            end

            # Reloads the currently loaded Aggressor script.
            #
            # @return [Hash] The new CNA catalog.
            def reload_cna
              raise CnaParser::Error, 'No CNA script is loaded.' unless @cna_catalog['path']

              load_cna(@cna_catalog['path'])
            end

            # Unloads all CNA-backed BOF aliases.
            #
            # @return [Hash] The empty CNA catalog.
            def unload_cna
              @cna_catalog = { 'path' => nil, 'bofs' => {}, 'warnings' => [] }
            end

            # Looks up one CNA-backed BOF.
            #
            # @param name [String] CNA alias name.
            # @return [Hash, nil] BOF definition when found.
            def cna_bof(name)
              @cna_catalog['bofs'][name]
            end

            # Resolves one CNA alias into native BOF execution input.
            #
            # @param name [String] CNA alias name.
            # @param arguments [Array<String>] Alias positional arguments.
            # @return [Hash] BOF bytes, packed values, format, and entry point.
            def cna_invocation(name, arguments: [])
              definition = cna_bof(name)
              raise CnaParser::Error, "Unknown CNA BOF: #{name}" unless definition

              bof_path = definition['files'][client.arch]
              unless bof_path && ::File.file?(bof_path) && ::File.readable?(bof_path)
                raise CnaParser::Error, "CNA alias '#{name}' has no readable BOF for #{client.arch}."
              end

              parsed = CnaArgumentParser.new(arguments: definition['arguments']).parse(arguments)
              {
                'data' => ::File.binread(bof_path),
                'entry' => definition['entry'],
                'format' => parsed['format'],
                'values' => parsed['values']
              }
            end

            # Executes a BOF in the current Meterpreter session.
            #
            # @param bof_data [String] COFF bytes.
            # @param args_format [String, nil] Cobalt Strike bof_pack format.
            # @param args [Array, nil] Values corresponding to args_format.
            # @param entry [String] Exported BOF entry point.
            # @return [String, nil] Captured BOF output.
            def execute(bof_data, args_format: nil, args: nil, entry: 'go')
              request = Packet.create_request(COMMAND_ID_BOFLOADER_EXECUTE)

              # Pack up beacon object file data and arguments into one single binary blob
              # Hardcode the entrypoint to "go" (CobaltStrike approved)
              bof = BofPack.new
              packed_args = bof.bof_pack(args_format, args)

              # Send the meterpreter TLV packet and get the output back
              request.add_tlv(TLV_TYPE_BOFLOADER_EXECUTE_BUFFER, bof_data)
              request.add_tlv(TLV_TYPE_BOFLOADER_EXECUTE_BUFFER_ENTRY, entry)
              request.add_tlv(TLV_TYPE_BOFLOADER_EXECUTE_ARGUMENTS, packed_args)
              response = client.send_request(request)
              return response.get_tlv_value(TLV_TYPE_BOFLOADER_EXECUTE_RESULT)
            end

          end
        end
      end
    end
  end
end
