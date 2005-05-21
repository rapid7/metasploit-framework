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
require 'Shared/ReadWriteLock'
require 'Shared/Transformer'

# Logging facilities
require 'Shared/Logging/LogSink'
require 'Shared/Logging/LogDispatcher'
