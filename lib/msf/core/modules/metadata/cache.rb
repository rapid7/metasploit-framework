require 'singleton'
require 'msf/events'
require 'rex/ui/text/output/stdio'
require 'msf/core/constants'
require 'msf/core/modules/metadata/obj'
require 'msf/core/modules/metadata/search'

#
# Core service class that provides storage of module metadata as well as operations on the metadata.
# Note that operations on this metadata are included as separate modules.
#
# To prevent excessive startup times module definitions are not parsed for metadata until startup
# is complete. Once startup is complete to prevent CPU spin loading is then done gradually and
# only when an operation using the cache is called is CPU use maximized.
#
module Msf
module Modules
module Metadata

class Cache
  include Singleton
  include ::Msf::UiEventSubscriber
  include Msf::Modules::Metadata::Search

  #
  # Init registers this class as a listener to be notified when the console is done loading,
  # this acts a hint to this class to start trickle loading the metadata
  #
  def init(framework)
    register_ui_listener(framework)
    @framework = framework
  end

  #
  # Parses module metadata into an in memory cache.
  #
  # @param klass_or_instance - An instantiated or class instance of a module.
  #
  def cache_module_metadata(klass_or_instance)
    # Only use cache if db is not in use for now
    return  if @framework.db.active

    if klass_or_instance.is_a?(Class)
      if @module_load_complete
        add_module_metadata_from_class(klass_or_instance)
      else
        @module_definitions << klass_or_instance
      end
    else
      add_module_metadata_from_instance(klass_or_instance)
    end
  end

  #########
  protected
  #########

  #
  # Notify the thread responsible for loading metadata that it can start loading.
  #
  def on_ui_start(rev)
    return if @module_load_complete
    @startup_called = true
  end

  #
  #  Returns the module data cache, but first ensures all the metadata is loaded
  #
  def get_module_metadata_cache
    wait_for_load
    return @module_metadata_cache
  end

  #######
  private
  #######

  def register_ui_listener(framework)
    begin
      framework.events.add_ui_subscriber(self)
    rescue Exception => e
      elog('Unable to register metadata cache service as UI listener')
    end
  end

  def wait_for_load
    if (!@module_load_complete)
      @trickle_load = false
      @console.print_warning('Waiting to finish parsing module metadata')
      @module_load_thread.join
    end
  end

  def add_module_metadata_from_class(module_class_definition)
    begin
      instance = module_class_definition.new
      add_module_metadata_from_instance(instance)
    rescue Exception => e
      elog("Error adding module metadata: #{e.message}")
    end
  end

  def add_module_metadata_from_instance(module_instance)
    module_metadata = Obj.new(module_instance)
    @module_metadata_cache[get_cache_key(module_instance)] = module_metadata
  end

  def get_cache_key(module_instance)
    key = ''
    key << (module_instance.type.nil? ? '' : module_instance.type)
    key << '_'
    key << module_instance.name
    return key
  end

  #
  # This method is used by the @module_load_thread
  #
  def load_module_definitions
    loop do
      if @startup_called
        break;
      end

      sleep 0.3
    end

    count = 0
    @module_definitions.each {|module_definition|
      add_module_metadata_from_class(module_definition)
      count = count + 1
      if (@trickle_load && count > @trickle_load_batch)
        sleep @trickle_load_interval
        count = 0
      end
    }

    @module_load_complete = true
    GC.start(full_mark: true, immediate_sweep: true)
  end

  def initialize
    @module_load_complete = false
    @startup_called = false;
    @trickle_load = true
    @trickle_load_batch = 200
    @trickle_load_interval = 0.5
    @module_metadata_cache = {}
    @module_definitions = []
    @module_load_thread = Thread.new {
      load_module_definitions
    }

    @console = Rex::Ui::Text::Output::Stdio.new
  end
end

end
end
end
