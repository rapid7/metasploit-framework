module CodeRay
  
  # = Plugin
  #
  #  Plugins have to include this module.
  #
  #  IMPORTANT: Use extend for this module.
  #
  #  See CodeRay::PluginHost for examples.
  module Plugin
    
    attr_reader :plugin_id
    
    # Register this class for the given +id+.
    # 
    # Example:
    #   class MyPlugin < PluginHost::BaseClass
    #     register_for :my_id
    #     ...
    #   end
    #
    # See PluginHost.register.
    def register_for id
      @plugin_id = id
      plugin_host.register self, id
    end
    
    # Returns the title of the plugin, or sets it to the
    # optional argument +title+.
    def title title = nil
      if title
        @title = title.to_s
      else
        @title ||= name[/([^:]+)$/, 1]
      end
    end
    
    # The PluginHost for this Plugin class.
    def plugin_host host = nil
      if host.is_a? PluginHost
        const_set :PLUGIN_HOST, host
      end
      self::PLUGIN_HOST
    end
    
    def aliases
      plugin_host.plugin_hash.inject [] do |aliases, (key, _)|
        aliases << key if plugin_host[key] == self
        aliases
      end
    end
    
  end
  
end
