require 'rex/ui'

module Rex
module Ui

###
#
# This output medium implements all the required output routines but does not
# back them against any sort of device.  This is basically meant to be put in
# place of something that expects to be able to deal with a functional output
# device when one does not actually exist.
#
###
class Output::None < Rex::Ui::Output
end

end
end