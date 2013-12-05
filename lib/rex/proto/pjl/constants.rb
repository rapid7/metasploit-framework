#
# https://en.wikipedia.org/wiki/Printer_Job_Language
#
# See external links for PJL spec
#

module Rex
module Proto
module PJL

# Miscellaneous constants
PJL_PREFIX = "@PJL"

# Kernel commands
PJL_UEL = "\e%-12345X"

# Status readback commands
PJL_INFO_ID = "#{PJL_PREFIX} INFO ID"
PJL_INFO_STATUS = "#{PJL_PREFIX} INFO STATUS"

# Device attendance commands
PJL_RDYMSG_DISPLAY = "#{PJL_PREFIX} RDYMSG DISPLAY"

end
end
end
