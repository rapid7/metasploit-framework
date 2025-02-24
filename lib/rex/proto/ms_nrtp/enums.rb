module Rex::Proto::MsNrtp
  module Enums
    OperationTypeEnum = {
      # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrtp/e64b2561-defe-4fb5-865e-ea6706c1253d
      Request: 0,
      OneWayRequest: 1,
      Reply: 2
    }
  end
end
