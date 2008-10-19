###
#
# Core option types.  The core supported option types are:
#
# OptString  - Multi-byte character string
# OptRaw     - Multi-byte raw string
# OptBool    - Boolean true or false indication
# OptPort    - TCP/UDP service port
# OptAddress - IP address or hostname
# OptPath    - Path name on disk
# OptInt     - An integer value
# OptEnum    - Select from a set of valid values
# OptAddressRange - A subnet or range of addresses
#
###

require 'msf/ui/gtk2/assistant/types/skeleton'

require 'msf/ui/gtk2/assistant/types/string'
require 'msf/ui/gtk2/assistant/types/raw'
require 'msf/ui/gtk2/assistant/types/bool'
require 'msf/ui/gtk2/assistant/types/port'
require 'msf/ui/gtk2/assistant/types/address'
require 'msf/ui/gtk2/assistant/types/path'
require 'msf/ui/gtk2/assistant/types/integer'

# TODO
#require 'msf/ui/gtk2/assistant/types/enum'
#require 'msf/ui/gtk2/assistant/types/addressrange'