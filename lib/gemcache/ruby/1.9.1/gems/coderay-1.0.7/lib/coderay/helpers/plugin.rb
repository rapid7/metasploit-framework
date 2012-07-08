module CodeRay
  
  # = PluginHost
  #
  # A simple subclass/subfolder plugin system.
  #
  # Example:
  #  class Generators
  #    extend PluginHost
  #    plugin_path 'app/generators'
  #  end
  #  
  #  class Generator
  #    extend Plugin
  #    PLUGIN_HOST = Generators
  #  end
  #  
  #  class FancyGenerator < Generator
  #    register_for :fancy
  #  end
  #  
  #  Generators[:fancy]  #-> FancyGenerator
  #  # or
  #  CodeRay.require_plugin 'Generators/fancy'
  #  # or
  #  Generators::Fancy
  module PluginHost
    
    # Raised if Encoders::[] fails because:
    # * a file could not be found
    # * the requested Plugin is not registered
    PluginNotFound = Class.new LoadError
    HostNotFound = Class.new LoadError
    
    PLUGIN_HOSTS = []
    PLUGIN_HOSTS_BY_ID = {}  # dummy hash
    
    # Loads all plugins using list and load.
    def load_all
      for plugin in list
        load plugin
      end
    end
    
    # Returns the Plugin for +id+.
    #
    # Example:
    #  yaml_plugin = MyPluginHost[:yaml]
    def [] id, *args, &blk
      plugin = validate_id(id)
      begin
        plugin = plugin_hash.[] plugin, *args, &blk
      end while plugin.is_a? Symbol
      plugin
    end
    
    alias load []
    
    # Tries to +load+ the missing plugin by translating +const+ to the
    # underscore form (eg. LinesOfCode becomes lines_of_code).
    def const_missing const
      id = const.to_s.
        gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
        gsub(/([a-z\d])([A-Z])/,'\1_\2').
        downcase
      load id
    end
    
    class << self
      
      # Adds the module/class to the PLUGIN_HOSTS list.
      def extended mod
        PLUGIN_HOSTS << mod
      end
      
    end
    
    # The path where the plugins can be found.
    def plugin_path *args
      unless args.empty?
        @plugin_path = File.expand_path File.join(*args)
      end
      @plugin_path ||= ''
    end
    
    # Map a plugin_id to another.
    #
    # Usage: Put this in a file plugin_path/_map.rb.
    #
    #  class MyColorHost < PluginHost
    #    map :navy => :dark_blue,
    #      :maroon => :brown,
    #      :luna => :moon
    #  end
    def map hash
      for from, to in hash
        from = validate_id from
        to = validate_id to
        plugin_hash[from] = to unless plugin_hash.has_key? from
      end
    end
    
    # Define the default plugin to use when no plugin is found
    # for a given id, or return the default plugin.
    #
    # See also map.
    #
    #  class MyColorHost < PluginHost
    #    map :navy => :dark_blue
    #    default :gray
    #  end
    #  
    #  MyColorHost.default  # loads and returns the Gray plugin
    def default id = nil
      if id
        id = validate_id id
        raise "The default plugin can't be named \"default\"." if id == :default
        plugin_hash[:default] = id
      else
        load :default
      end
    end
    
    # Every plugin must register itself for +id+ by calling register_for,
    # which calls this method.
    #
    # See Plugin#register_for.
    def register plugin, id
      plugin_hash[validate_id(id)] = plugin
    end
    
    # A Hash of plugion_id => Plugin pairs.
    def plugin_hash
      @plugin_hash ||= make_plugin_hash
    end
    
    # Returns an array of all .rb files in the plugin path.
    #
    # The extension .rb is not included.
    def list
      Dir[path_to('*')].select do |file|
        File.basename(file)[/^(?!_)\w+\.rb$/]
      end.map do |file|
        File.basename(file, '.rb').to_sym
      end
    end
    
    # Returns an array of all Plugins.
    # 
    # Note: This loads all plugins using load_all.
    def all_plugins
      load_all
      plugin_hash.values.grep(Class)
    end
    
    # Loads the map file (see map).
    #
    # This is done automatically when plugin_path is called.
    def load_plugin_map
      mapfile = path_to '_map'
      @plugin_map_loaded = true
      if File.exist? mapfile
        require mapfile
        true
      else
        false
      end
    end
    
  protected
    
    # Return a plugin hash that automatically loads plugins.
    def make_plugin_hash
      @plugin_map_loaded ||= false
      Hash.new do |h, plugin_id|
        id = validate_id(plugin_id)
        path = path_to id
        begin
          require path
        rescue LoadError => boom
          if @plugin_map_loaded
            if h.has_key?(:default)
              warn '%p could not load plugin %p; falling back to %p' % [self, id, h[:default]]
              h[:default]
            else
              raise PluginNotFound, '%p could not load plugin %p: %s' % [self, id, boom]
            end
          else
            load_plugin_map
            h[plugin_id]
          end
        else
          # Plugin should have registered by now
          if h.has_key? id
            h[id]
          else
            raise PluginNotFound, "No #{self.name} plugin for #{id.inspect} found in #{path}."
          end
        end
      end
    end
    
    # Returns the expected path to the plugin file for the given id.
    def path_to plugin_id
      File.join plugin_path, "#{plugin_id}.rb"
    end
    
    # Converts +id+ to a Symbol if it is a String,
    # or returns +id+ if it already is a Symbol.
    #
    # Raises +ArgumentError+ for all other objects, or if the
    # given String includes non-alphanumeric characters (\W).
    def validate_id id
      if id.is_a? Symbol or id.nil?
        id
      elsif id.is_a? String
        if id[/\w+/] == id
          id.downcase.to_sym
        else
          raise ArgumentError, "Invalid id given: #{id}"
        end
      else
        raise ArgumentError, "String or Symbol expected, but #{id.class} given."
      end
    end
    
  end
  
  
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
      plugin_host.load_plugin_map
      plugin_host.plugin_hash.inject [] do |aliases, (key, _)|
        aliases << key if plugin_host[key] == self
        aliases
      end
    end
    
  end
  
end
