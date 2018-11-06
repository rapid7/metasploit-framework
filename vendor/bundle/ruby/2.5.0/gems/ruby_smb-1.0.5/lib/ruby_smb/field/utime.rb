require 'date'

module RubySMB
  module Field
    # Conveneince class for dealing with 32-bit unsigned UTIME
    # fields in SMB, as defined in
    # [2.2.1.4.3 UTIME](https://msdn.microsoft.com/en-us/library/ee441907.aspx)
    class Utime < BinData::Primitive
      endian :little
      uint32 :val

      # Gets the value of the field
      #
      # @return [BinData::Bit32] the 64-bit value of the field
      def get
        val
      end

      # Sets the value of the field from a DateTime,Time,Fixnum, or object
      # that can be converted to an integer. Any other
      # parameter passed in will be assumed to already be correct.
      #
      # @param value [DateTime,Time,Fixnum,#to_i] the value to set
      # @return
      def set(value)
        case value
        when DateTime
          set(value.to_time)
        when Time
          set(value.to_i)
        when Integer
          self.val = value
        else
          self.val = value.to_i
        end
        val
      end

      # Returns the value of the field as a {DateTime}
      #
      # @return [DateTime] the {DateTime} representation of the current value
      def to_datetime
        time = to_time
        time.to_datetime
      end

      # Returns the value of the field as a {Time}
      #
      # @return [Time] the {Time} representation of the current value
      def to_time
        Time.at val
      end
    end
  end
end
