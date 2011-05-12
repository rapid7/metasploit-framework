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

# Set the log source, and initialize demand-loaded requires
module Msf
	LogSource = "core"

	# Event subscriber interfaces
	autoload :UiEventSubscriber, 'msf/events'

	# Wrappers
	autoload :EncodedPayload, 'msf/core/encoded_payload'

	# Pseudo-modules
	autoload :Handler, 'msf/core/handler'

	# Mixins
	autoload :Encoder,       'msf/core/encoder'
	autoload :EncoderState,  'msf/core/encoder'
	autoload :Auxiliary,     'msf/core/auxiliary'
	autoload :Nop,           'msf/core/nop'
	autoload :Payload,       'msf/core/payload'
	autoload :ExploitEvent,  'msf/core/exploit'
	autoload :Exploit,       'msf/core/exploit'
	autoload :Post,          'msf/core/post'

	# Drivers
	autoload :ExploitDriver, 'msf/core/exploit_driver'

	# Framework context and core classes
	autoload :Framework, 'msf/core/framework'

	# Session stuff
	autoload :Session,      'msf/core/session'
	autoload :SessionEvent, 'msf/core/session'
end

# General
require 'msf/core/constants'
require 'msf/core/exceptions'
require 'msf/core/data_store'
require 'msf/core/option_container'

# Modules
require 'msf/core/module'
