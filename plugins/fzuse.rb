module Msf
  ###
  #
  # This class illustrates a fuzzy_use plugin.  Plugins can change the behavior of
  # the framework by adding new features, new user interface commands, or
  # through any other arbitrary means.  They are designed to have a very loose
  # definition in order to make them as useful as possible.
  #
  ###
  class Plugin::FuzzyUse < Msf::Plugin

    ###
    #
    # This class implements a fuzzy_use console command dispatcher.
    #
    ###
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def initialize(driver)
        super

        @module_dispatcher = Msf::Ui::Console::CommandDispatcher::Modules.new(driver)
      end

      #
      # The dispatcher's name.
      #
      def name
        'FuzzyUse'
      end

      #
      # Returns the hash of commands supported by this dispatcher.
      #
      def commands
        {
          'fzuse' => 'A fuzzy_use command added by the fuzzy_use plugin'
        }
      end

      #
      # This method handles the fuzzy_use command.
      #
      def cmd_fzuse(*args)
        unless Msf::Util::Helper.which('fzf')
          print_error('This command requires that the `fzf` utility be installed.')
          return
        end

        previewer = File.join(Msf::Config.install_root, 'tools', 'modules', 'print.py')

        module_types = framework.modules.module_types

        query = args.empty? ? '' : args.first
      
        selection = nil
        # alternative preview:
        # jq \'to_entries[] | select(.value.fullname == "{1}") | .value\' db/modules_metadata_base.json | bat --language=json --color=always
        stdin, stdout, stderr, wait_thr = Open3.popen3('fzf', '--select-1', '--query', query, '--preview', "#{previewer} {1}", '--preview-label', "Module Information") do |stdin, stdout, stderr, wait_thr|
          module_types
          module_types.each do |module_type|
            framework.modules.module_names(module_type).each do |module_name|
              stdin.puts "#{module_type}/#{module_name}"
            end
          end
          stdin.close

          exit_status = wait_thr.value
          
          selection = stdout.read
        end

        selection.strip!
        return if selection.blank?
        
        @module_dispatcher.cmd_use(selection)
      end
    end

    #
    # The constructor is called when an instance of the plugin is created.  The
    # framework instance that the plugin is being associated with is passed in
    # the framework parameter.  Plugins should call the parent constructor when
    # inheriting from Msf::Plugin to ensure that the framework attribute on
    # their instance gets set.
    #
    def initialize(framework, opts)
      super

      # If this plugin is being loaded in the context of a console application
      # that uses the framework's console user interface driver, register
      # console dispatcher commands.
      add_console_dispatcher(ConsoleCommandDispatcher)

      print_status('FuzzyUse plugin loaded.')
    end

    #
    # The cleanup routine for plugins gives them a chance to undo any actions
    # they may have done to the framework.  For instance, if a console
    # dispatcher was added, then it should be removed in the cleanup routine.
    #
    def cleanup
      # If we had previously registered a console dispatcher with the console,
      # deregister it now.
      remove_console_dispatcher('FuzzyUse')
    end

    #
    # This method returns a short, friendly name for the plugin.
    #
    def name
      'fuzzy_use'
    end

    #
    # This method returns a brief description of the plugin.  It should be no
    # more than 60 characters, but there are no hard limits.
    #
    def desc
      'Demonstrates using framework plugins'
    end

  end
end
