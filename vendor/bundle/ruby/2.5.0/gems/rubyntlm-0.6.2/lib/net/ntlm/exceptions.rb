module Net
  module NTLM
    class NtlmError < StandardError; end

    class InvalidTargetDataError < NtlmError
      attr_reader :data

      def initialize(msg, data)
        @data = data
        super(msg)
      end
    end
  end
end
