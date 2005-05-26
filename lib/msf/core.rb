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

# framework-core depends on framework-shared
require 'Msf/Shared'

# General
require 'Msf/Core/Constants'
require 'Msf/Core/Exceptions'
require 'Msf/Core/DataTypes'
require 'Msf/Core/EventDispatcher'
require 'Msf/Core/DataStore'
require 'Msf/Core/OptionContainer'

# Framework context and core classes
require 'Msf/Core/ModuleManager'
require 'Msf/Core/SessionManager'
require 'Msf/Core/Session'
require 'Msf/Core/Framework'

# Modules
require 'Msf/Core/Module'
require 'Msf/Core/Encoder'
require 'Msf/Core/Exploit'
require 'Msf/Core/Nop'
require 'Msf/Core/Recon'
