###
#
# framework-core
# --------------
#
# The core library provides all of the means by which to interact
# with the framework insofar as maniuplating encoders, nops,
# payloads, exploits, recon, and sessions.
#
###

# framework-core depends on Rex
require 'rex'
require 'rex/ui'

module Msf
	LogSource = "core"
end

# General
require 'msf/core/constants'
require 'msf/core/exceptions'
require 'msf/core/event_dispatcher'
require 'msf/core/data_store'
require 'msf/core/option_container'

# Framework context and core classes
require 'msf/core/framework'
require 'msf/core/session_manager'
require 'msf/core/session'
require 'msf/core/plugin_manager'

# Wrappers
require 'msf/core/encoded_payload'

# Pseudo-modules
require 'msf/core/handler'

# Modules
require 'msf/core/module'
require 'msf/core/encoder'
require 'msf/core/exploit'
require 'msf/core/nop'
require 'msf/core/payload'
require 'msf/core/recon'

# Drivers
require 'msf/core/exploit_driver'
