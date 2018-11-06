require 'date'

module RubySMB
  module Field
    # Represents a Windows FILETIME structure as defined in
    # [FILETIME structure](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx)
    class FileTime < BinData::Primitive
      # Difference between the Windows and Unix epochs, in 100ns intervals
      EPOCH_DIFF_100NS = 116_444_736_000_000_000
      NS_MULTIPLIER = 10_000_000
      endian :little
      uint64 :val

      # Gets the value of the field
      #
      # @return [BinData::Bit64] the 64-bit value of the field
      def get
        val
      end

      # Sets the value of the field from a DateTime,Time,Fixnum, or object
      # that can be converted to an integer. Datetime and Time objects get
      # converted to account for the Windows/Unix Epoch difference. Any other
      # parameter passed in will be assumed to already be correct.
      #
      # @param value [DateTime,Time,Fixnum,#to_i] the value to set
      # @return
      def set(value)
        case value
        when DateTime
          set(value.to_time)
        when Time
          time_int = value.to_i
          time_int *= NS_MULTIPLIER
          adjusted_epoch = time_int + EPOCH_DIFF_100NS
          set(adjusted_epoch)
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
        windows_int = val
        adjusted_epoch = windows_int - EPOCH_DIFF_100NS
        unix_int = adjusted_epoch / NS_MULTIPLIER
        Time.at unix_int
      end
    end
  end
end
