require 'rex/proto/ntlm'
require 'rex/arch'
include Rex::Arch

NTLM_CONST   ||= ::Rex::Proto::NTLM::Constants
NTLM_CRYPT   ||= ::Rex::Proto::NTLM::Crypt
NTLM_UTILS   ||= ::Rex::Proto::NTLM::Utils
NTLM_BASE    ||= ::Rex::Proto::NTLM::Base
NTLM_MESSAGE ||= ::Rex::Proto::NTLM::Message

module Msf

  LogSource = "core"
end

require 'msf/core/exception' # TODO: temporary require until we can split up the exceptions file and namespace properly
require 'msf_autoload'
