
class BitStruct
  class Field
    # Offset of field in bits.
    attr_reader :offset

    # Length of field in bits.
    attr_reader :length
    alias size length

    # Name of field (used for its accessors).
    attr_reader :name

    # Options, such as :default (varies for each field subclass).
    # In general, options can be provided as strings or as symbols.
    attr_reader :options

    # Display name of field (used for printing).
    attr_reader :display_name

    # Default value.
    attr_reader :default

    # Format for printed value of field.
    attr_reader :format

    # Subclasses can override this to define a default for all fields of this
    # class, not just the one currently being added to a BitStruct class, a
    # "default default" if you will. The global default, if #default returns
    # nil, is to fill the field with zero. Most field classes just let this
    # default stand. The default can be overridden per-field when a BitStruct
    # class is defined.
    def self.default; nil; end

    # Used in describe.
    def self.class_name
      @class_name ||= name[/\w+$/]
    end

    # Used in describe. Can be overridden per-subclass, as in NestedField.
    def class_name
      self.class.class_name
    end

    # Yield the description of this field, as an array of 5 strings: byte
    # offset, type, name, size, and description. The opts hash may have:
    #
    # :expand ::  if the value is true, expand complex fields
    #
    # (Subclass implementations may yield more than once for complex fields.)
    #
    def describe opts
      bits = size
      if bits > 32 and bits % 8 == 0
        len_str = "%dB" % (bits/8)
      else
        len_str = "%db" % bits
      end

      byte_offset = offset / 8 + (opts[:byte_offset] || 0)

      yield ["@%d" % byte_offset, class_name, name, len_str, display_name]
    end

    # Options are _display_name_, _default_, and _format_ (subclasses of Field
    # may add other options).
    def initialize(offset, length, name, opts = {})
      @offset, @length, @name, @options =
        offset, length, name, opts

      @display_name = opts[:display_name] || opts["display_name"]
      @default      = opts[:default] || opts["default"] || self.class.default
      @format       = opts[:format] || opts["format"]
    end

    # Inspect the value of this field in the specified _obj_.
    def inspect_in_object(obj, opts)
      val = obj.send(name)
      str =
        begin
          val.inspect_with_options(opts)
        rescue NoMethodError
          val.inspect
        end
      (f=@format) ? (f % str) : str
    end

    # Normally, all fields show up in inspect, but some, such as padding,
    # should not.
    def inspectable?; true; end
  end
end


