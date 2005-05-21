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

# Unit testing
require 'test/unit'
require 'Core/UnitTestSuite'

# framework-core depends on framework-shared
require 'Shared'

# General
require 'Core/Constants'
require 'Core/Exceptions'
require 'Core/DataTypes'
require 'Core/EventDispatcher'
require 'Core/DataStore'

# Framework context and core classes
require 'Core/Framework'
require 'Core/Session'

# Modules
require 'Core/Module'
require 'Core/Encoder'
require 'Core/Exploit'
require 'Core/Nop'
require 'Core/Recon'
