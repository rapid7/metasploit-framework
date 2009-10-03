class BitStruct
  # Class for fixed length padding.
  class PadField < Field
    # Used in describe.
    def self.class_name
      @class_name ||= "padding"
    end

    def add_accessors_to(cl, attr = name) # :nodoc:
      # No accessors for padding.
    end

    def inspectable?; false; end
  end
end
