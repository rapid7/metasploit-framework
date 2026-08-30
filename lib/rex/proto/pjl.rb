# -*- coding: binary -*-

# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL

  require "rex/proto/pjl/client"

  DEFAULT_PORT = 9100
  DEFAULT_TIMEOUT = 5

  COUNT_MAX = 2_147_483_647
  SIZE_MAX = 2_147_483_647

  UEL = "\e%-12345X" # Universal Exit Language
  PREFIX = "@PJL"

  module Info
    ID = "#{PREFIX} INFO ID"
    STATUS = "#{PREFIX} INFO STATUS"
    VARIABLES = "#{PREFIX} INFO VARIABLES"
    FILESYS = "#{PREFIX} INFO FILESYS"
  end

  RDYMSG = "#{PREFIX} RDYMSG"

  FSINIT = "#{PREFIX} FSINIT"
  FSQUERY = "#{PREFIX} FSQUERY"
  FSDIRLIST = "#{PREFIX} FSDIRLIST"
  FSUPLOAD = "#{PREFIX} FSUPLOAD"
  FSDOWNLOAD = "#{PREFIX} FSDOWNLOAD"
  FSDELETE = "#{PREFIX} FSDELETE"

end
