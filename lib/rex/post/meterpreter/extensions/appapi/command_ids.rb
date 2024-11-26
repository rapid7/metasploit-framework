# -*- coding: binary -*-
# CorrM @ fb.me/IslamNofl

module Rex
module Post
module Meterpreter
module Extensions
module AppApi

# ID for the extension (needs to be a multiple of 1000)
EXTENSION_ID_APPAPI = 9000

# Associated command ids
COMMAND_ID_APPAPI_APP_INSTALL   = EXTENSION_ID_APPAPI + 1
COMMAND_ID_APPAPI_APP_LIST      = EXTENSION_ID_APPAPI + 2
COMMAND_ID_APPAPI_APP_RUN       = EXTENSION_ID_APPAPI + 3
COMMAND_ID_APPAPI_APP_UNINSTALL = EXTENSION_ID_APPAPI + 4

end; end; end; end; end

