require 'msf/ui'

module Msf
module Ui
module Console

###
#
# Shell
# -----
#
# The shell class provides a command-prompt style interface in a 
# generic fashion.  This wrapper is just here in case we want to do custom
# shell extensions that don't make sense to throw in the rex shell.
#
###
module Shell

	include Rex::Ui::Text::Shell

end

end end end
