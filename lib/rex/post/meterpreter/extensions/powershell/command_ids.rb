# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Powershell

# ID for the extension (needs to be a multiple of 1000)
EXTENSION_ID_POWERSHELL = 14000

# Associated command ids
COMMAND_ID_POWERSHELL_ASSEMBLY_LOAD  = EXTENSION_ID_POWERSHELL + 1
COMMAND_ID_POWERSHELL_EXECUTE        = EXTENSION_ID_POWERSHELL + 2
COMMAND_ID_POWERSHELL_SESSION_REMOVE = EXTENSION_ID_POWERSHELL + 3
COMMAND_ID_POWERSHELL_SHELL          = EXTENSION_ID_POWERSHELL + 4

end
end
end
end
end
