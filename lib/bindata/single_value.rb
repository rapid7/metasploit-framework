require 'bindata/single'
require 'bindata/struct'

module BinData
  # A SingleValue is a declarative way to define a new BinData data type.
  # The data type must contain a single value only.  For new data types
  # that contain multiple values see BinData::MultiValue.
  #
  # To define a new data type, set fields as if for MultiValue and add a
  # #get and #set method to extract / convert the data between the fields
  # and the #value of the object.
  #
  #    require 'bindata'
  #
  #    class PascalString < BinData::SingleValue
  #      uint8  :len,  :value => lambda { data.length }
  #      string :data, :read_length => :len
  #    
  #      def get
  #        self.data
  #      end
  #    
  #      def set(v)
  #        self.data = v
  #      end
  #    end
  #
  #    ps = PascalString.new(:initial_value => "hello")
  #    ps.to_s #=> "\005hello"
  #    ps.read("\003abcde")
  #    ps.value #=> "abc"
  #
  #    # Unsigned 24 bit big endian integer
  #    class Uint24be < BinData::SingleValue
  #      uint8 :byte1
  #      uint8 :byte2
  #      uint8 :byte3
  #
  #      def get
  #        (self.byte1 << 16) | (self.byte2 << 8) | self.byte3
  #      end
  #
  #      def set(v)
  #        v = 0 if v < 0
  #        v = 0xffffff if v > 0xffffff
  #
  #        self.byte1 = (v >> 16) & 0xff
  #        self.byte2 = (v >>  8) & 0xff
  #        self.byte3 =  v        & 0xff
  #      end
  #    end
  #
  #    u24 = Uint24be.new
  #    u24.read("\x12\x34\x56")
  #    "0x%x" % u24.value #=> 0x123456
  #
  # == Parameters
  #
  # SingleValue objects accept all the parameters that BinData::Single do.
  #
  class SingleValue < Single

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

      # Returns all stored fields.  Should only be called by
      # #sanitize_parameters
      def fields
        @fields || []
      end

      # Used to define fields for the internal structure.
      def method_missing(symbol, *args)
        name, params = args

        type = symbol
        name = (name.nil? or name == "") ? nil : name.to_s
        params ||= {}

        # note that fields are stored in an instance variable not a class var
        @fields ||= []

        # check that type is known
        unless Sanitizer.type_exists?(type, endian)
          raise TypeError, "unknown type '#{type}' for #{self}", caller
        end

        # check that name is okay
        if name != nil
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
        end

        # remember this field.  These fields will be recalled upon creating
        # an instance of this class
        @fields.push([type, name, params])
      end

      # Ensures that +params+ is of the form expected by #initialize.
      def sanitize_parameters!(sanitizer, params)
        struct_params = {}
        struct_params[:fields] = self.fields
        struct_params[:endian] = self.endian unless self.endian.nil?
        
        params[:struct_params] = struct_params

        super(sanitizer, params)
      end
    end

    # These are the parameters used by this class.
    mandatory_parameter :struct_params

    def initialize(params = {}, env = nil)
      super(params, env)

      @struct = BinData::Struct.new(param(:struct_params), create_env)
    end

    # Forward method calls to the internal struct.
    def method_missing(symbol, *args, &block)
      if @struct.respond_to?(symbol)
        @struct.__send__(symbol, *args, &block)
      else
        super
      end
    end

    #---------------
    private

    # Retrieve a sensible default from the internal struct.
    def sensible_default
      get
    end

    # Read data into the fields of the internal struct then return the value.
    def read_val(io)
      @struct.read(io)
      get
    end

    # Sets +val+ into the fields of the internal struct then returns the
    # string representation.
    def val_to_str(val)
      set(val)
      @struct.to_s
    end

    ###########################################################################
    # To be implemented by subclasses

    # Extracts the value for this data object from the fields of the
    # internal struct.
    def get
      raise NotImplementedError
    end

    # Sets the fields of the internal struct to represent +v+.
    def set(v)
      raise NotImplementedError
    end

    # To be implemented by subclasses
    ###########################################################################
  end
end