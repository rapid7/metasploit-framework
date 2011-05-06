##
# $Id: $
#
# maps autoload for logging classes
##

require 'rex/constants' # for LEV_'s

module Rex
module Logging
	autoload :LogSink,       'rex/logging/log_sink'
	autoload :Sinks,         'rex/logging/sinks'
end
end

# This defines a global so it must be loaded always
require 'rex/logging/log_dispatcher'
