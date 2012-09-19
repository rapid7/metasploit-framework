module JSON
  MAP = {
    "\x0" => '\u0000',
    "\x1" => '\u0001',
    "\x2" => '\u0002',
    "\x3" => '\u0003',
    "\x4" => '\u0004',
    "\x5" => '\u0005',
    "\x6" => '\u0006',
    "\x7" => '\u0007',
    "\b"  =>  '\b',
    "\t"  =>  '\t',
    "\n"  =>  '\n',
    "\xb" => '\u000b',
    "\f"  =>  '\f',
    "\r"  =>  '\r',
    "\xe" => '\u000e',
    "\xf" => '\u000f',
    "\x10" => '\u0010',
    "\x11" => '\u0011',
    "\x12" => '\u0012',
    "\x13" => '\u0013',
    "\x14" => '\u0014',
    "\x15" => '\u0015',
    "\x16" => '\u0016',
    "\x17" => '\u0017',
    "\x18" => '\u0018',
    "\x19" => '\u0019',
    "\x1a" => '\u001a',
    "\x1b" => '\u001b',
    "\x1c" => '\u001c',
    "\x1d" => '\u001d',
    "\x1e" => '\u001e',
    "\x1f" => '\u001f',
    '"'   =>  '\"',
    '\\'  =>  '\\\\',
  } # :nodoc:

  # Convert a UTF8 encoded Ruby string _string_ to a JSON string, encoded with
  # UTF16 big endian characters as \u????, and return it.
  if defined?(::Encoding)
    def utf8_to_json(string) # :nodoc:
      string = string.dup
      string << '' # XXX workaround: avoid buffer sharing
      string.force_encoding(::Encoding::ASCII_8BIT)
      string.gsub!(/["\\\x0-\x1f]/) { MAP[$&] }
      string.force_encoding(::Encoding::UTF_8)
      string
    end

    def utf8_to_json_ascii(string) # :nodoc:
      string = string.dup
      string << '' # XXX workaround: avoid buffer sharing
      string.force_encoding(::Encoding::ASCII_8BIT)
      string.gsub!(/["\\\x0-\x1f]/) { MAP[$&] }
      string.gsub!(/(
                      (?:
                        [\xc2-\xdf][\x80-\xbf]    |
                        [\xe0-\xef][\x80-\xbf]{2} |
                        [\xf0-\xf4][\x80-\xbf]{3}
                      )+ |
                      [\x80-\xc1\xf5-\xff]       # invalid
                    )/nx) { |c|
                      c.size == 1 and raise GeneratorError, "invalid utf8 byte: '#{c}'"
                      s = JSON.iconv('utf-16be', 'utf-8', c).unpack('H*')[0]
                      s.gsub!(/.{4}/n, '\\\\u\&')
                    }
      string.force_encoding(::Encoding::UTF_8)
      string
    rescue => e
      raise GeneratorError, "Caught #{e.class}: #{e}"
    end
  else
    def utf8_to_json(string) # :nodoc:
      string.gsub(/["\\\x0-\x1f]/) { MAP[$&] }
    end

    def utf8_to_json_ascii(string) # :nodoc:
      string = string.gsub(/["\\\x0-\x1f]/) { MAP[$&] }
      string.gsub!(/(
                      (?:
                        [\xc2-\xdf][\x80-\xbf]    |
                        [\xe0-\xef][\x80-\xbf]{2} |
                        [\xf0-\xf4][\x80-\xbf]{3}
                      )+ |
                      [\x80-\xc1\xf5-\xff]       # invalid
                    )/nx) { |c|
        c.size == 1 and raise GeneratorError, "invalid utf8 byte: '#{c}'"
        s = JSON.iconv('utf-16be', 'utf-8', c).unpack('H*')[0]
        s.gsub!(/.{4}/n, '\\\\u\&')
      }
      string
    rescue => e
      raise GeneratorError, "Caught #{e.class}: #{e}"
    end
  end
  module_function :utf8_to_json, :utf8_to_json_ascii

  module Pure
    module Generator
      # This class is used to create State instances, that are use to hold data
      # while generating a JSON text from a Ruby data structure.
      class State
        # Creates a State object from _opts_, which ought to be Hash to create
        # a new State instance configured by _opts_, something else to create
        # an unconfigured instance. If _opts_ is a State object, it is just
        # returned.
        def self.from_state(opts)
          case
          when self === opts
            opts
          when opts.respond_to?(:to_hash)
            new(opts.to_hash)
          when opts.respond_to?(:to_h)
            new(opts.to_h)
          else
            SAFE_STATE_PROTOTYPE.dup
          end
        end

        # Instantiates a new State object, configured by _opts_.
        #
        # _opts_ can have the following keys:
        #
        # * *indent*: a string used to indent levels (default: ''),
        # * *space*: a string that is put after, a : or , delimiter (default: ''),
        # * *space_before*: a string that is put before a : pair delimiter (default: ''),
        # * *object_nl*: a string that is put at the end of a JSON object (default: ''),
        # * *array_nl*: a string that is put at the end of a JSON array (default: ''),
        # * *check_circular*: is deprecated now, use the :max_nesting option instead,
        # * *max_nesting*: sets the maximum level of data structure nesting in
        #   the generated JSON, max_nesting = 0 if no maximum should be checked.
        # * *allow_nan*: true if NaN, Infinity, and -Infinity should be
        #   generated, otherwise an exception is thrown, if these values are
        #   encountered. This options defaults to false.
        # * *quirks_mode*: Enables quirks_mode for parser, that is for example
        #   generating single JSON values instead of documents is possible.
        def initialize(opts = {})
          @indent                = ''
          @space                 = ''
          @space_before          = ''
          @object_nl             = ''
          @array_nl              = ''
          @allow_nan             = false
          @ascii_only            = false
          @quirks_mode           = false
          @buffer_initial_length = 1024
          configure opts
        end

        # This string is used to indent levels in the JSON text.
        attr_accessor :indent

        # This string is used to insert a space between the tokens in a JSON
        # string.
        attr_accessor :space

        # This string is used to insert a space before the ':' in JSON objects.
        attr_accessor :space_before

        # This string is put at the end of a line that holds a JSON object (or
        # Hash).
        attr_accessor :object_nl

        # This string is put at the end of a line that holds a JSON array.
        attr_accessor :array_nl

        # This integer returns the maximum level of data structure nesting in
        # the generated JSON, max_nesting = 0 if no maximum is checked.
        attr_accessor :max_nesting

        # If this attribute is set to true, quirks mode is enabled, otherwise
        # it's disabled.
        attr_accessor :quirks_mode

        # :stopdoc:
        attr_reader :buffer_initial_length

        def buffer_initial_length=(length)
          if length > 0
            @buffer_initial_length = length
          end
        end
        # :startdoc:

        # This integer returns the current depth data structure nesting in the
        # generated JSON.
        attr_accessor :depth

        def check_max_nesting # :nodoc:
          return if @max_nesting.zero?
          current_nesting = depth + 1
          current_nesting > @max_nesting and
            raise NestingError, "nesting of #{current_nesting} is too deep"
        end

        # Returns true, if circular data structures are checked,
        # otherwise returns false.
        def check_circular?
          !@max_nesting.zero?
        end

        # Returns true if NaN, Infinity, and -Infinity should be considered as
        # valid JSON and output.
        def allow_nan?
          @allow_nan
        end

        # Returns true, if only ASCII characters should be generated. Otherwise
        # returns false.
        def ascii_only?
          @ascii_only
        end

        # Returns true, if quirks mode is enabled. Otherwise returns false.
        def quirks_mode?
          @quirks_mode
        end

        # Configure this State instance with the Hash _opts_, and return
        # itself.
        def configure(opts)
          @indent         = opts[:indent] if opts.key?(:indent)
          @space          = opts[:space] if opts.key?(:space)
          @space_before   = opts[:space_before] if opts.key?(:space_before)
          @object_nl      = opts[:object_nl] if opts.key?(:object_nl)
          @array_nl       = opts[:array_nl] if opts.key?(:array_nl)
          @allow_nan      = !!opts[:allow_nan] if opts.key?(:allow_nan)
          @ascii_only     = opts[:ascii_only] if opts.key?(:ascii_only)
          @depth          = opts[:depth] || 0
          @quirks_mode    = opts[:quirks_mode] if opts.key?(:quirks_mode)
          if !opts.key?(:max_nesting) # defaults to 19
            @max_nesting = 19
          elsif opts[:max_nesting]
            @max_nesting = opts[:max_nesting]
          else
            @max_nesting = 0
          end
          self
        end
        alias merge configure

        # Returns the configuration instance variables as a hash, that can be
        # passed to the configure method.
        def to_h
          result = {}
          for iv in %w[indent space space_before object_nl array_nl allow_nan max_nesting ascii_only quirks_mode buffer_initial_length depth]
            result[iv.intern] = instance_variable_get("@#{iv}")
          end
          result
        end

        # Generates a valid JSON document from object +obj+ and returns the
        # result. If no valid JSON document can be created this method raises a
        # GeneratorError exception.
        def generate(obj)
          result = obj.to_json(self)
          unless @quirks_mode
            unless result =~ /\A\s*\[/ && result =~ /\]\s*\Z/ ||
              result =~ /\A\s*\{/ && result =~ /\}\s*\Z/
            then
              raise GeneratorError, "only generation of JSON objects or arrays allowed"
            end
          end
          result
        end

        # Return the value returned by method +name+.
        def [](name)
          __send__ name
        end
      end

      module GeneratorMethods
        module Object
          # Converts this object to a string (calling #to_s), converts
          # it to a JSON string, and returns the result. This is a fallback, if no
          # special method #to_json was defined for some object.
          def to_json(*) to_s.to_json end
        end

        module Hash
          # Returns a JSON string containing a JSON object, that is unparsed from
          # this Hash instance.
          # _state_ is a JSON::State object, that can also be used to configure the
          # produced JSON string output further.
          # _depth_ is used to find out nesting depth, to indent accordingly.
          def to_json(state = nil, *)
            state = State.from_state(state)
            state.check_max_nesting
            json_transform(state)
          end

          private

          def json_shift(state)
            state.object_nl.empty? or return ''
            state.indent * state.depth
          end

          def json_transform(state)
            delim = ','
            delim << state.object_nl
            result = '{'
            result << state.object_nl
            depth = state.depth += 1
            first = true
            indent = !state.object_nl.empty?
            each { |key,value|
              result << delim unless first
              result << state.indent * depth if indent
              result << key.to_s.to_json(state)
              result << state.space_before
              result << ':'
              result << state.space
              result << value.to_json(state)
              first = false
            }
            depth = state.depth -= 1
            result << state.object_nl
            result << state.indent * depth if indent if indent
            result << '}'
            result
          end
        end

        module Array
          # Returns a JSON string containing a JSON array, that is unparsed from
          # this Array instance.
          # _state_ is a JSON::State object, that can also be used to configure the
          # produced JSON string output further.
          def to_json(state = nil, *)
            state = State.from_state(state)
            state.check_max_nesting
            json_transform(state)
          end

          private

          def json_transform(state)
            delim = ','
            delim << state.array_nl
            result = '['
            result << state.array_nl
            depth = state.depth += 1
            first = true
            indent = !state.array_nl.empty?
            each { |value|
              result << delim unless first
              result << state.indent * depth if indent
              result << value.to_json(state)
              first = false
            }
            depth = state.depth -= 1
            result << state.array_nl
            result << state.indent * depth if indent
            result << ']'
          end
        end

        module Integer
          # Returns a JSON string representation for this Integer number.
          def to_json(*) to_s end
        end

        module Float
          # Returns a JSON string representation for this Float number.
          def to_json(state = nil, *)
            state = State.from_state(state)
            case
            when infinite?
              if state.allow_nan?
                to_s
              else
                raise GeneratorError, "#{self} not allowed in JSON"
              end
            when nan?
              if state.allow_nan?
                to_s
              else
                raise GeneratorError, "#{self} not allowed in JSON"
              end
            else
              to_s
            end
          end
        end

        module String
          if defined?(::Encoding)
            # This string should be encoded with UTF-8 A call to this method
            # returns a JSON string encoded with UTF16 big endian characters as
            # \u????.
            def to_json(state = nil, *args)
              state = State.from_state(state)
              if encoding == ::Encoding::UTF_8
                string = self
              else
                string = encode(::Encoding::UTF_8)
              end
              if state.ascii_only?
                '"' << JSON.utf8_to_json_ascii(string) << '"'
              else
                '"' << JSON.utf8_to_json(string) << '"'
              end
            end
          else
            # This string should be encoded with UTF-8 A call to this method
            # returns a JSON string encoded with UTF16 big endian characters as
            # \u????.
            def to_json(state = nil, *args)
              state = State.from_state(state)
              if state.ascii_only?
                '"' << JSON.utf8_to_json_ascii(self) << '"'
              else
                '"' << JSON.utf8_to_json(self) << '"'
              end
            end
          end

          # Module that holds the extinding methods if, the String module is
          # included.
          module Extend
            # Raw Strings are JSON Objects (the raw bytes are stored in an
            # array for the key "raw"). The Ruby String can be created by this
            # module method.
            def json_create(o)
              o['raw'].pack('C*')
            end
          end

          # Extends _modul_ with the String::Extend module.
          def self.included(modul)
            modul.extend Extend
          end

          # This method creates a raw object hash, that can be nested into
          # other data structures and will be unparsed as a raw string. This
          # method should be used, if you want to convert raw strings to JSON
          # instead of UTF-8 strings, e. g. binary data.
          def to_json_raw_object
            {
              JSON.create_id  => self.class.name,
              'raw'           => self.unpack('C*'),
            }
          end

          # This method creates a JSON text from the result of
          # a call to to_json_raw_object of this String.
          def to_json_raw(*args)
            to_json_raw_object.to_json(*args)
          end
        end

        module TrueClass
          # Returns a JSON string for true: 'true'.
          def to_json(*) 'true' end
        end

        module FalseClass
          # Returns a JSON string for false: 'false'.
          def to_json(*) 'false' end
        end

        module NilClass
          # Returns a JSON string for nil: 'null'.
          def to_json(*) 'null' end
        end
      end
    end
  end
end
