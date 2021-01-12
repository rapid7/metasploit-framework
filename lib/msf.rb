
require 'rex/arch'
include Rex::Arch

module Msf

  LogSource = "core"
end

require 'msf/core/exception' # TODO: temporary require until we can split up the exceptions file and namespace properly
require 'msf_autoload'
