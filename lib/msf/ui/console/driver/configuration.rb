# Concerning the loading and saving of the framework configuration into {Msf::Ui::Console::Driver}.
module Msf::Ui::Console::Driver::Configuration
  #
  # CONSTANTS
  #

  CONFIG_CORE  = 'framework/core'
  CONFIG_GROUP = 'framework/ui/console'

  #
  # Methods
  #

  # Loads configuration for the console.
  #
  # @return [void]
  def load_config(path=nil)
    begin
      conf = Msf::Config.load(path)
    rescue
      wlog("Failed to load configuration: #{$!}")
      return
    end

    # If we have configuration, process it
    if (conf.group?(CONFIG_GROUP))
      conf[CONFIG_GROUP].each_pair { |k, v|
        case k.downcase
          when "activemodule"
            run_single("use #{v}")
        end
      }
    end
  end

  # Loads configuration that needs to be analyzed before the {Msf::Ui::Console::Driver#framework} is created.
  #
  # @return [void]
  def load_preconfig
    begin
      conf = Msf::Config.load
    rescue
      wlog("Failed to load configuration: #{$!}")
      return
    end

    if (conf.group?(CONFIG_CORE))
      conf[CONFIG_CORE].each_pair { |k, v|
        on_variable_set(true, k, v)
      }
    end
  end

  # Saves configuration for the console.
  #
  # @return [void]
  def save_config
    # Build out the console config group
    group = {}

    if (metasploit_instance)
      group['ActiveModule'] = metasploit_instance.fullname
    end

    # Save it
    begin
      Msf::Config.save(CONFIG_GROUP => group)
    rescue ::Exception
      print_error("Failed to save console config: #{$!}")
    end
  end
end
