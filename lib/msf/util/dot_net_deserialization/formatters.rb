module Msf
module Util
module DotNetDeserialization
module Formatters

require 'msf/util/dot_net_deserialization/formatters/binary_formatter'
require 'msf/util/dot_net_deserialization/formatters/los_formatter'
require 'msf/util/dot_net_deserialization/formatters/soap_formatter'

NAMES = [
  :BinaryFormatter,
  :LosFormatter,
  :SoapFormatter
]

end
end
end
end
