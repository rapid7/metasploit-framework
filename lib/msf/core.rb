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

# Sanity check this version of ruby
require 'msf/sanity'

# The framework-core depends on Rex
require 'rex'
require 'rex/ui'

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

# General
require 'msf/core/constants'
require 'msf/core/exceptions'
require 'msf/core/data_store'
require 'msf/core/option_container'

# Event subscriber interfaces
require 'msf/events'

# Framework context and core classes
require 'msf/core/framework'
require 'msf/core/db_manager'
require 'msf/core/event_dispatcher'
require 'msf/core/module_manager'
require 'msf/core/module_set'
require 'msf/core/plugin_manager'
require 'msf/core/session'
require 'msf/core/session_manager'



# Wrappers
require 'msf/core/encoded_payload'

# Pseudo-modules
require 'msf/core/handler'

# Modules
require 'msf/core/module'
require 'msf/core/encoder'
require 'msf/core/auxiliary'
require 'msf/core/exploit'
require 'msf/core/nop'
require 'msf/core/payload'
require 'msf/core/post'

# Custom HTTP Modules
require 'msf/http/wordpress'
require 'msf/http/typo3'
require 'msf/http/jboss'

# Kerberos Support
require 'msf/kerberos/client'

# Java RMI Support
require 'msf/java/rmi/util'
require 'msf/java/rmi/client'

# Drivers
require 'msf/core/exploit_driver'

