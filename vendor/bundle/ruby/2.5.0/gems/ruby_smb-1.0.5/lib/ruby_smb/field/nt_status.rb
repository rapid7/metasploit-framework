require 'windows_error/nt_status'

module RubySMB
  module Field
    # Represents an NTStatus code as defined in
    # [2.3.1 NTSTATUS values](https://msdn.microsoft.com/en-us/library/cc704588.aspx)
    class NtStatus < BinData::Uint32le
      # Returns a meaningful error code parsed from the numeric value
      #
      # @return [WindowsError::ErrorCode] the ErrorCode object for this code
      def to_nt_status
        WindowsError::NTStatus.find_by_retval(value).first
      end
    end
  end
end
