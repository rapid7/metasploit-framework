# This can be removed once rack/rack@2fd9df71 is released
module Sinatra
  module Ext
    def self.get_handler(str)
      begin
        ::Object.const_get("Object", false)
        def self._const_get(str, inherit = true)
          Rack::Handler.const_get(str, inherit)
        end
      rescue
        def self._const_get(str, inherit = true)
          Rack::Handler.const_get(str)
        end
      end
    end
  end
end
