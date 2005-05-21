###
#
# framework-shared
# ----------------
#
# The shared library in the framework contains classes that are
# used by various framework subsystems.
#
###

# Shared single purpose classes
require 'Msf/Shared/ReadWriteLock'
require 'Msf/Shared/Transformer'

# Logging facilities
require 'Msf/Shared/Logging/LogSink'
require 'Msf/Shared/Logging/LogDispatcher'
