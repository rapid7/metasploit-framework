# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL

  require "rex/proto/pjl/client"

  UEL = "\e%-12345X" # Universal Exit Language
  PREFIX = "@PJL"

  INFO_ID = "#{PREFIX} INFO ID"
  INFO_STATUS = "#{PREFIX} INFO STATUS"

  RDYMSG_DISPLAY = "#{PREFIX} RDYMSG DISPLAY"

end
