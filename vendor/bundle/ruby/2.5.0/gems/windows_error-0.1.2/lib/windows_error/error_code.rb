module WindowsError

  # This is the core class that represents a Windows Error Code.
  # It maps the error code value to the description of the error
  # according to Microsoft documentation found at [Windows Error Codes](https://msdn.microsoft.com/en-us/library/cc231196.aspx)
  class ErrorCode
    # @return [String] the description of the error the code represents
    attr_reader :description
    # @return [String] the name of the error code
    attr_reader :name
    # @return [Integer] the error code that was given as a return value
    attr_reader :value

    # @param [String] name the 'name' of the error code (i.e STATUS_SUCCESS)
    # @param [Integer] value the return value that represents that error
    # @param [String] description the verbose description of the error
    # @raise [ArgumentError] if any of the parameters are of an invalid type
    def initialize(name, value, description)
      raise ArgumentError, 'Invalid Error Name!' unless name.kind_of? String and !(name.empty?)
      raise ArgumentError, 'Invalid Error Code Value!' unless value.kind_of? Integer
      raise ArgumentError, 'Invalid Error Description!' unless description.kind_of? String and !(description.empty?)
      @name = name
      @value = value
      @description = description
      @name.freeze
      @value.freeze
      @description.freeze
      self.freeze
    end

    # Overirdes the equality test for ErrorCodes. Equality is
    # always tested against the #value of the error code.
    #
    # @param [Object] other_object the object to test equality against
    # @raise [ArgumentError] if the other object is not either another ErrorCode or a Integer
    # @return [Boolean] whether the equality test passed
    def ==(other_object)
      if other_object.kind_of? self.class
        self.value == other_object.value
      elsif other_object.kind_of? Integer
        self.value == other_object
      else
        raise ArgumentError, "Cannot compare a #{self.class} to a #{other_object.class}"
      end
    end

    alias :=== :==

    def to_s
      code = sprintf "%08x", self.value
      "(0x#{code}) #{self.name}: #{self.description}"
    end
  end


end
