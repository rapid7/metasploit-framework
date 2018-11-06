require 'backports/tools/alias_method'

class << ARGF
  Backports.alias_method self, :lines, :each_line
end
