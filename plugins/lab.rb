##
# $Id$
# $Revision$
##

$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '..', 'lib', 'lab'))

require 'yaml'

module Msf

class Plugin::Lab < Msf::Plugin
  class LabCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    attr_accessor :controller

    def initialize(driver)
      super(driver)
      @controller = nil
      
      #
      # Require the lab gem, but fail nicely if it's not there. 
      #
      begin
        require 'lab'
      rescue LoadError
        raise "WARNING: Lab gem not found, Please 'gem install lab'"
      end
      
    end

    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands
    {
      "lab_help" => "lab_help <lab command> - Show that command's description.",
      "lab_show" => "lab_show - show all vms in the lab.",
      "lab_search" => "lab_search - search local vms in the lab.",
      "lab_search_tags" => "lab_search_tag - search local vms in the lab.",
      #"lab_search_remote" => "lab_search_remote - search remote vms in the lab.",
      "lab_show_running" => "lab_show_running - show running vms.",
      "lab_load" => "lab_load [file] - load a lab definition from disk.",
      "lab_save" => "lab_save [filename] - persist a lab definition in a file.",
      "lab_load_running" => "lab_load_running [type] [user] [host] - use the running vms to create a lab.",
      "lab_load_config" => "lab_load_config [type] [user] [host] - use the vms in the config to create a lab.",
      "lab_load_dir" => "lab_load_dir [type] [directory] - create a lab from a specified directory.",
      "lab_clear" => "lab_clear - clear the running lab.",
      "lab_start" => "lab_start [vmid+|all] start the specified vm.",
      "lab_reset" => "lab_reset [vmid+|all] reset the specified vm.",
      "lab_suspend" => "lab_suspend [vmid+|all] suspend the specified vm.",
      "lab_stop" => "lab_stop [vmid+|all] stop the specified vm.",
      "lab_revert" => "lab_revert [vmid+|all] [snapshot] revert the specified vm.",
      "lab_snapshot" => "lab_snapshot [vmid+|all] [snapshot] snapshot all targets for this exploit.",
      "lab_upload" => "lab_upload [vmid] [local_path] [remote_path] upload a file.",
      "lab_run_command" => "lab_run_command [vmid+|all] [command] run a command on all targets.",
      "lab_browse_to" => "lab_browse_to [vmid+|all] [uri] use the default browser to browse to a uri."
    }
    end

    def name
      "Lab"
    end

    ##
    ## Regular Lab Commands
    ##

    def cmd_lab_load(*args)
      return lab_usage unless args.count == 1

      res = args[0]
      good_res = nil
      if (File.file? res and File.readable? res)
        # then the provided argument is an absolute path and is gtg.
        good_res = res
      elsif
        # let's check to see if it's in the data/lab dir (like when tab completed)
        [
          ::Msf::Config.data_directory + File::SEPARATOR + "lab",
          # there isn't a user_data_directory, but could use:
          #::Msf::Config.user_plugins_directory + File::SEPARATOR + "lab"
        ].each do |dir|
          res_path = dir + File::SEPARATOR + res 
          if (File.file?(res_path) and File.readable?(res_path))
            good_res = res_path
            break
          end
        end
      end
      if good_res
        @controller.from_file(good_res)
      else
        print_error("#{res} is not a valid lab definition file (.yml)")
      end
    end
  
    #
    # Tab completion for the lab_load command
    #
    def cmd_lab_load_tabs(str, words)
      tabs = []
      #return tabs if words.length > 1
      if ( str and str =~ /^#{Regexp.escape(File::SEPARATOR)}/ )
        # then you are probably specifying a full path so let's just use normal file completion
        return tab_complete_filenames(str,words)
      elsif (not words[1] or not words[1].match(/^\//))
        # then let's start tab completion in the data/lab directory
        begin
          [
            ::Msf::Config.data_directory + File::SEPARATOR + "lab",
            # there isn't a user_data_directory, but could use:
            #::Msf::Config.user_plugins_directory + File::SEPARATOR + "lab"
          ].each do |dir|
            next if not ::File.exist? dir
            tabs += ::Dir.new(dir).find_all { |e|
              path = dir + File::SEPARATOR + e
              ::File.file?(path) and File.readable?(path)
            }
          end
        rescue Exception
        end
      else
        tabs += tab_complete_filenames(str,words)
      end
      return tabs
    end

    def cmd_lab_load_dir(*args)
      return lab_usage unless args.count == 2
      @controller.build_from_dir(args[0],args[1],true)
    end

    def cmd_lab_clear(*args)
      @controller.clear!
    end

    def cmd_lab_save(*args)
      return lab_usage if args.empty?
      @controller.to_file(args[0])
    end

    def cmd_lab_load_running(*args)
      return lab_usage if args.empty?

      if args[0] =~ /^remote_/
        return lab_usage unless args.count == 3
        ## Expect a username & password
        @controller.build_from_running(args[0], args[1], args[2])
      else
        return lab_usage unless args.count == 1
        @controller.build_from_running(args[0])
      end
    end

    def cmd_lab_load_config(*args)
      return lab_usage if args.empty?

      if args[0] =~ /^remote_/
        return lab_usage unless args.count == 3
        ## Expect a username & password
        @controller.build_from_config(args[0], args[1], args[2])
      else
        return lab_usage unless args.count == 1
        @controller.build_from_config(args[0])
      end
    end

    def cmd_lab_load_dir(*args)
      return lab_usage unless args.count == 2
      @controller.build_from_dir(args[0],args[1],true)
    end

    def cmd_lab_clear(*args)
      @controller.clear!
    end

    def cmd_lab_save(*args)
      return lab_usage if args.empty?
      @controller.to_file(args[0])
    end


    ##
    ## Commands for dealing with a currently-loaded lab
    ##
    def cmd_lab_show(*args)
      if args.empty?
        hlp_print_lab
      else
        args.each do |name|
          if @controller.includes_hostname? name
            print_line @controller[name].to_yaml
          else
            print_error "Unknown vm '#{name}'"
          end
        end
      end
    end

    def cmd_lab_show_running(*args)
      hlp_print_lab_running
    end


    def cmd_lab_search(*args)
      if args.empty?
        hlp_print_lab
      else
        args.each do |arg|
          print_line "Searching for vms with hostname matching #{arg}"
          @controller.each do |vm|
            print_line "checking to see #{vm.hostname} matches #{arg}"
            print_line "#{vm.hostname} matched #{arg}" if vm.hostname =~ Regexp.new(arg)
          end
        end
      end
    end

    def cmd_lab_search_tags(*args)
      if args.empty?
        hlp_print_lab
      else
        args.each do |arg|
          print_line "Searching for vms with tags matching #{arg}"
          @controller.each do |vm|
            print_line "checking to see #{vm.hostname} is tagged #{arg}"
            print_line "#{vm.hostname} tagged #{arg}" if vm.tagged?(arg)
          end
        end	
      end
    end


    def cmd_lab_start(*args)
      return lab_usage if args.empty?

      if args[0] == "all"
        @controller.each do |vm|
          print_line "Starting lab vm #{vm.hostname}."
          if !vm.running?
            vm.start
          else
            print_line "Lab vm #{vm.hostname} already running."
          end
        end
      else
        args.each do |arg|
          if @controller.includes_hostname? arg
            vm = @controller.find_by_hostname(arg)
            if !vm.running?
              print_line "Starting lab vm #{vm.hostname}."
              vm.start
            else
              print_line "Lab vm #{vm.hostname} already running."
            end
          end
        end
      end
    end

    def cmd_lab_stop(*args)
      return lab_usage if args.empty?

      if args[0] == "all"
        @controller.each do |vm|
          print_line "Stopping lab vm #{vm.hostname}."
          if vm.running?
            vm.stop
          else
            print_line "Lab vm #{vm.hostname} not running."
          end
        end
      else
        args.each do |arg|
          if @controller.includes_hostname? arg
            vm = @controller.find_by_hostname(arg)
            if vm.running?
              print_line "Stopping lab vm #{vm.hostname}."
              vm.stop
            else
              print_line "Lab vm #{vm.hostname} not running."
            end
          end
        end
      end
    end

    def cmd_lab_suspend(*args)
      return lab_usage if args.empty?

      if args[0] == "all"
        @controller.each{ |vm| vm.suspend }
      else
        args.each do |arg|
          if @controller.includes_hostname? arg
            if @controller.find_by_hostname(arg).running?
              print_line "Suspending lab vm #{arg}."
              @controller.find_by_hostname(arg).suspend
            end
          end
        end
      end
    end

    def cmd_lab_reset(*args)
      return lab_usage if args.empty?

      if args[0] == "all"
        print_line "Resetting all lab vms."
        @controller.each{ |vm| vm.reset }
      else
        args.each do |arg|
          if @controller.includes_hostname? arg
            if @controller.find_by_hostname(arg).running?
              print_line "Resetting lab vm #{arg}."
              @controller.find_by_hostname(arg).reset
            end
          end
        end
      end
    end


    def cmd_lab_snapshot(*args)
      return lab_usage if args.count < 2
      snapshot = args[args.count-1]

      if args[0] == "all"
        print_line "Snapshotting all lab vms to snapshot: #{snapshot}."
        @controller.each{ |vm| vm.create_snapshot(snapshot) }
      else
        args[0..-2].each do |name_arg|
          next unless @controller.includes_hostname? name_arg
          print_line "Snapshotting #{name_arg} to snapshot: #{snapshot}."
          @controller[name_arg].create_snapshot(snapshot)
        end
      end
    end


    def cmd_lab_revert(*args)
      return lab_usage if args.count < 2
      snapshot = args[args.count-1]

      if args[0] == "all"
        print_line "Reverting all lab vms to snapshot: #{snapshot}."
        @controller.each{ |vm| vm.revert_snapshot(snapshot) }
      else
        args[0..-2].each do |name_arg|
          next unless @controller.includes_hostname? name_arg
          print_line "Reverting #{name_arg} to snapshot: #{snapshot}."
          @controller[name_arg].revert_snapshot(snapshot)
        end
      end
    end


    def cmd_lab_run_command(*args)
      return lab_usage if args.empty?
      command = args[args.count-1]
      if args[0] == "all"
        print_line "Running command #{command} on all vms."
          @controller.each do |vm|
            if vm.running?
              print_line "#{vm.hostname} running command: #{command}."
              vm.run_command(command)
            end
          end
      else
        args[0..-2].each do |name_arg|
          next unless @controller.includes_hostname? name_arg
          if @controller[name_arg].running?
            print_line "#{name_arg} running command: #{command}."
            @controller[name_arg].run_command(command)
          end
        end
      end
    end

    # 
    # Command: lab_upload [vmids] [from] [to]
    # 
    # Description: Uploads a file to the guest(s)
    #
    # Quirks: Pass "all" as a vmid to have it operate on all vms.
    # 
    def cmd_lab_upload(*args)
      return lab_usage if args.empty?
      return lab_usage if args.count < 3

      local_path = args[args.count-2]
      vm_path = args[args.count-1]

      if args[0] == "all"
          @controller.each do |vm|
            if vm.running?
                print_line "Copying from #{local_path} to #{vm_path} on #{vm.hostname}"
                vm.copy_to_guest(local_path, vm_path)
            end
          end
      else
        args[0..-2].each do |vmid_arg|
          next unless @controller.includes_hostname? vmid_arg
          if @controller[vmid_arg].running?
            print_line "Copying from #{local_path} to #{vm_path} on #{vmid_arg}"
            @controller[vmid_arg].copy_to_guest(local_path, vm_path)
          end
        end
      end
    end

    def cmd_lab_browse_to(*args)
      return lab_usage if args.empty?
      uri = args[args.count-1]
      if args[0] == "all"
        print_line "Opening: #{uri} on all vms."
        @controller.each do |vm|
          if vm.running?
            print_line "#{vm.hostname} opening to uri: #{uri}."
            vm.open_uri(uri)
          end
        end
      else
        args[0..-2].each do |name_arg|
          next unless @controller.includes_hostname? name_arg
          if @controller[name_arg].running?
            print_line "#{name_arg} opening to uri: #{uri}."
            @controller[name_arg].open_uri(uri)
          end
        end
      end
    end


    ##
    ## Commands for help
    ##

    def longest_cmd_size
      commands.keys.map {|x| x.size}.sort.last
    end

    # No extended help yet, but this is where more detailed documentation
    # on particular commands would live. Key is command, (not cmd_command),
    # value is the documentation.
    def extended_help
      {
        "lab_fake_cmd" =>              "This is a fake command. It's got its own special docs." +
          (" " * longest_cmd_size) + "It might be long so so deal with formatting somehow."
      }
    end

    # Map for usages
    def lab_usage
      caller[0][/`cmd_(.*)'/]
      cmd = $1
      if extended_help[cmd] || commands[cmd]
        cmd_lab_help cmd
      else # Should never really get here...
        print_error "Unknown command. Try 'help'"
      end
    end

    def cmd_lab_help(*args)
      if args.empty?
        commands.each_pair {|k,v| print_line "%-#{longest_cmd_size}s - %s" % [k,v] }
      else
        args.each do |c|
          if extended_help[c] || commands[c]
            print_line "%-#{longest_cmd_size}s - %s" % [c,extended_help[c] || commands[c]]
          else
            print_error "Unknown command '#{c}'"
          end
        end
      end

      print_line
      print_line "In order to use this plugin, you'll want to configure a .yml lab file"
      print_line "You can find an example in data/lab/test_targets.yml"
      print_line
    end


    private
      def hlp_print_lab
        indent = '    '

        tbl = Rex::Text::Table.new(
          'Header'  => 'Available Lab VMs',
          'Indent'  => indent.length,
          'Columns' => [ 'Hostname', 'Driver', 'Type' ]
        )

        @controller.each do |vm|
          tbl << [ 	vm.hostname,
              vm.driver.class, 
              vm.type]
        end

        print_line tbl.to_s
      end

      def hlp_print_lab_running
        indent = '    '

        tbl = Rex::Text::Table.new(
          'Header'  => 'Running Lab VMs',
          'Indent'  => indent.length,
          'Columns' => [ 'Hostname', 'Driver', 'Type', 'Power?' ]
        )

        @controller.each do |vm|
          if vm.running?
            tbl << [ 	vm.hostname,
                vm.driver.class,
                vm.type,
                vm.running?]
          end
        end
        print_line tbl.to_s
      end


  end

  #
  # The constructor is called when an instance of the plugin is created.  The
  # framework instance that the plugin is being associated with is passed in
  # the framework parameter.  Plugins should call the parent constructor when
  # inheriting from Msf::Plugin to ensure that the framework attribute on
  # their instance gets set.
  #
  attr_accessor :controller
  
  def initialize(framework, opts)
    super

    ## Register the commands above
    console_dispatcher = add_console_dispatcher(LabCommandDispatcher)

    @controller = ::Lab::Controllers::VmController.new

    ## Share the vms
    console_dispatcher.controller = @controller
  end


  #
  # The cleanup routine for plugins gives them a chance to undo any actions
  # they may have done to the framework.  For instance, if a console
  # dispatcher was added, then it should be removed in the cleanup routine.
  #
  def cleanup
    # If we had previously registered a console dispatcher with the console,
    # deregister it now.
    remove_console_dispatcher('Lab')
  end

  #
  # This method returns a short, friendly name for the plugin.
  #
  def name
    "lab"
  end

  #
  # This method returns a brief description of the plugin.  It should be no
  # more than 60 characters, but there are no hard limits.
  #
  def desc
    "Adds the ability to manage VMs"
  end

end ## End Class
end ## End Module	
