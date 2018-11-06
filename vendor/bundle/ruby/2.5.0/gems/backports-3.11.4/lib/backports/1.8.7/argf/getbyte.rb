require 'backports/tools/alias_method'

class << ARGF
  Backports.alias_method self, :getbyte, :getc
end
