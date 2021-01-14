# -*- coding: binary -*-
###
#
# framework-core
# --------------
#
# The core library provides all of the means by which to interact
# with the framework insofar as manipulating encoders, nops,
# payloads, exploits, auxiliary, and sessions.
#
###

# The framework-core depends on Rex
require 'rex'
require 'rex/ui'
require 'rex/arch'

include Rex::Arch

NTLM_CONST   ||= ::Rex::Proto::NTLM::Constants
NTLM_CRYPT   ||= ::Rex::Proto::NTLM::Crypt
NTLM_UTILS   ||= ::Rex::Proto::NTLM::Utils
NTLM_BASE    ||= ::Rex::Proto::NTLM::Base
NTLM_MESSAGE ||= ::Rex::Proto::NTLM::Message

module Msf
  autoload :Author, 'msf/core/author'
  autoload :Platform, 'msf/core/platform'
  autoload :Reference, 'msf/core/reference'
  autoload :SiteReference, 'msf/core/site_reference'
  autoload :Target, 'msf/core/target'

  #
  # Constants
  #

  LogSource = "core"
end

# Event subscriber interfaces
require 'msf/events'
