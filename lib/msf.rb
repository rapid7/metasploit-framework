require 'rex/arch'
require 'rex/logging'

include Rex::Arch
include Rex::Logging

module Msf

  LogSource = "core"
end

require 'msf/core/exception' # TODO: temporary require until we can split up the exceptions file and namespace properly
require 'msf/core/constants'
require 'msf_autoload'

MsfAutoload.instance

NTLM_CONST   ||= ::Rex::Proto::NTLM::Constants
NTLM_CRYPT   ||= ::Rex::Proto::NTLM::Crypt
NTLM_UTILS   ||= ::Rex::Proto::NTLM::Utils
NTLM_BASE    ||= ::Rex::Proto::NTLM::Base
NTLM_MESSAGE ||= ::Rex::Proto::NTLM::Message
