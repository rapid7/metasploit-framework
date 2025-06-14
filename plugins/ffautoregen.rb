module Msf
  ###
  #
  # This plugin reloads and re-executes a file-format exploit module once it has changed.
  #
  ###
  class Plugin::FFAutoRegen < Msf::Plugin

    ###
    #
    # This class implements a single edit command.
    #
    ###
    class FFAutoRegenCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      #
      # The dispatcher's name.
      #
      def name
        'FFAutoRegen'
      end

      #
      # Returns the hash of commands supported by this dispatcher.
      #
      def commands
        {
          'ffautoregen' => 'Automatically regenerate the document when the exploit source changes'
        }
      end

      #
      # This method handles the command.
      #
      def cmd_ffautoregen(*_args)
        if !active_module || !(path = active_module.file_path)
          print_line('Error: No active module selected')
          return nil
        end

        last = mt = File.stat(path).mtime

        loop do
          sleep(1)
          mt = File.stat(path).mtime

          next unless (mt != last)

          last = mt

          nmod = framework.modules.reload_module(active_module)
          if !nmod
            print_line('Error: Failed to reload module, trying again on next change...')
            next
          end

          jobify = false
          payload = nmod.datastore['PAYLOAD']
          encoder = nmod.datastore['ENCODER']
          target = nmod.datastore['TARGET']
          nop = nmod.datastore['NOP']

          nmod.exploit_simple(
            'Encoder' => encoder,
            'Payload' => payload,
            'Target' => target,
            'Nop' => nop,
            #						'OptionStr'      => opt_str,
            'LocalInput' => driver.input,
            'LocalOutput' => driver.output,
            'RunAsJob' => jobify
          )
        end
      end
    end

    def initialize(framework, opts)
      super

      # console dispatcher commands.
      add_console_dispatcher(FFAutoRegenCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('FFAutoRegen')
    end

    def name
      'ffautoregen'
    end

    def desc
      'This plugin reloads and re-executes a file-format exploit module once it has changed'
    end

  end
end
