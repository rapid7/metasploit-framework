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

# Parse SVN entries
require 'msf/util/svn'

# Custom ActiveRecord serialization via base64 (Marshal)
require "msf/util/base64_serializer.rb"
