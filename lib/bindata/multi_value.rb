require 'bindata/struct'

module BinData
  # A MultiValue is a declarative wrapper around Struct.
  #
  #    require 'bindata'
  #
  #    class Tuple < BinData::MultiValue
  #      int8  :x
  #      int8  :y
  #      int8  :z
  #    end
  #
  #    class SomeDataType < BinData::MultiValue
  #      hide 'a'
  #
  #      int32le :a
  #      int16le :b
  #      tuple   :s
  #    end
  #
  #    obj = SomeDataType.new
  #    obj.field_names   =># ["b", "s"]
  #
  #
  # == Parameters
  #
  # Parameters may be provided at initialisation to control the behaviour of
  # an object.  These params are:
  #
  # <tt>:fields</tt>::   An array specifying the fields for this struct.
  #                      Each element of the array is of the form [type, name,
  #                      params].  Type is a symbol representing a registered
  #                      type.  Name is the name of this field.  Params is an
  #                      optional hash of parameters to pass to this field
  #                      when instantiating it.
  # <tt>:hide</tt>::     A list of the names of fields that are to be hidden
  #                      from the outside world.  Hidden fields don't appear
  #                      in #snapshot or #field_names but are still accessible
  #                      by name.
  # <tt>:endian</tt>::   Either :little or :big.  This specifies the default
  #                      endian of any numerics in this struct, or in any
  #                      nested data objects.
  class MultiValue < BinData::Struct

    class << self
      # Register the names of all subclasses of this class.
      def inherited(subclass) #:nodoc:
        register(subclass.name, subclass)
      end

      # Returns or sets the endianess of numerics used in this stucture.
      # Endianess is applied to the fields of this structure.
      # Valid values are :little and :big.
      def endian(endian = nil)
        @endian ||= nil
        if [:little, :big].include?(endian)
          @endian = endian
        elsif endian != nil
          raise ArgumentError, "unknown value for endian '#{endian}'"
        end
        @endian
      end

      # Returns the names of any hidden fields in this struct.  Any given args
      # are appended to the hidden list.
      def hide(*args)
        # note that fields are stored in an instance variable not a class var
        @hide ||= []
        @hide.concat(args.collect { |name| name.to_s })
        @hide
      end

      # Returns all stored fields.
      # Should only be called by #sanitize_parameters
      def fields
        @fields ||= []
      end

      # Used to define fields for this structure.
      def method_missing(symbol, *args)
        name, params = args

        type = symbol
        name = name.to_s
        params ||= {}

        # note that fields are stored in an instance variable not a class var
        @fields ||= []

        # check that type is known
        unless Sanitizer.type_exists?(type, endian)
          raise TypeError, "unknown type '#{type}' for #{self}", caller
        end

        # check for duplicate names
        @fields.each do |t, n, p|
          if n == name
            raise SyntaxError, "duplicate field '#{name}' in #{self}", caller
          end
        end

        # check that name doesn't shadow an existing method
        if self.instance_methods.include?(name)
          raise NameError.new("", name),
                "field '#{name}' shadows an existing method", caller
        end

        # check that name isn't reserved
        if self::RESERVED.include?(name)
          raise NameError.new("", name),
                "field '#{name}' is a reserved name", caller
        end

        # remember this field.  These fields will be recalled upon creating
        # an instance of this class
        @fields.push([type, name, params])
      end

      # Ensures that +params+ is of the form expected by #initialize.
      def sanitize_parameters!(sanitizer, params)
        endian = params[:endian] || self.endian
        fields = params[:fields] || self.fields
        hide   = params[:hide]   || self.hide

        params[:endian] = endian unless endian.nil?
        params[:fields] = fields
        params[:hide]   = hide

        super(sanitizer, params)
      end
    end
  end
end