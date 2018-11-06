module Net
module NTLM

  # base classes for primitives
  # @private
  class Field
    attr_accessor :active, :value

    def initialize(opts)
      @value  = opts[:value]
      @active = opts[:active].nil? ? true : opts[:active]
      @size   = opts[:size].nil? ? 0 : opts[:size]
    end

    def size
      @active ? @size : 0
    end

    # Serializer function for field data
    # Exists in this class to be overridden by child classes
    def serialize
      raise NotImplementedError
    end

    # Parser function for field data
    # Exists in this class to be overridden by child classes
    def parse(str, offset=0)
      raise NotImplementedError
    end

  end


end
end