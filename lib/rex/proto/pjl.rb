# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL

  require "rex/proto/pjl/client"

  COUNT_MAX = 2147483647
  SIZE_MAX = 2147483647

  UEL = "\e%-12345X" # Universal Exit Language
  PREFIX = "@PJL"

  module Info
    ID = "#{PREFIX} INFO ID"
    STATUS = "#{PREFIX} INFO STATUS"
    FILESYS = "#{PREFIX} INFO FILESYS"
  end

  RDYMSG = "#{PREFIX} RDYMSG"

  FSINIT = "#{PREFIX} FSINIT"
  FSDIRLIST = "#{PREFIX} FSDIRLIST"
  FSUPLOAD = "#{PREFIX} FSUPLOAD"

end
