# https://en.wikipedia.org/wiki/Printer_Job_Language
# See external links for PJL spec

module Rex::Proto::PJL

  require "rex/proto/pjl/client"

  COUNT_MAX = 2147483647
  SIZE_MAX = 2147483647

  UEL = "\e%-12345X" # Universal Exit Language
  PREFIX = "@PJL"

  INFO_ID = "#{PREFIX} INFO ID"
  INFO_STATUS = "#{PREFIX} INFO STATUS"
  INFO_FILESYS = "#{PREFIX} INFO FILESYS"

  RDYMSG_DISPLAY = "#{PREFIX} RDYMSG DISPLAY"

  FSINIT_VOLUME = "#{PREFIX} FSINIT VOLUME"
  FSDIRLIST_NAME = "#{PREFIX} FSDIRLIST NAME"
  FSUPLOAD_NAME = "#{PREFIX} FSUPLOAD NAME"

end
