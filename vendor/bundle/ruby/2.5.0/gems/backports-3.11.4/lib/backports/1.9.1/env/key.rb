require 'backports/tools/alias_method'

class << ENV
  Backports.alias_method self, :key, :index
end
