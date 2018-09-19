# -*- coding: binary -*-
###
#
# framework-util
# --------------
#
# The util library miscellaneous routines that involve the framework
# API, but are not directly related to the core/base/ui structure.
#
###


require 'msf/core'
require 'rex'

module Msf
module Util

end
end

# Executable generation and encoding
require 'msf/util/exe'
require 'msf/util/helper'

# Host helpers
require 'msf/util/host'

# DBManager helpers
require 'msf/util/db_manager'
