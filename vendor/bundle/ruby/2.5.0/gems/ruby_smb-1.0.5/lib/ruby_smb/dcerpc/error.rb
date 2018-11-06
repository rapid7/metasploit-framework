module RubySMB
  # Contains all the DCERPC specific Error classes.
  module Dcerpc
    module Error
      # Base class for DCERPC errors
      class DcerpcError < RubySMB::Error::RubySMBError; end

      # Raised when The Bind operation fails
      class BindError < DcerpcError; end

      # Raised when an invalid packet is received
      class InvalidPacket < DcerpcError; end
    end
  end
end
