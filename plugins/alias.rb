require 'rex/text/table'

module Msf

class Plugin::Alias < Msf::Plugin
  class AliasCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    attr_reader :aliases
    def initialize(driver)
      super(driver)
      @aliases = {}
    end

    def name
      "Alias"
    end

    @@alias_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help banner."                    ],
      "-c" => [ true, "Clear an alias (* to clear all)."],
      "-f" => [ true,  "Force an alias assignment."      ]
    )
    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands # driver.dispatcher_stack[3].commands
      {
        "alias" => "create or view an alias."
  #			"alias_clear" => "clear an alias (or all aliases).",
  #			"alias_force" => "Force an alias (such as to override)"
      }.merge(aliases) # make aliased commands available as commands of their own
    end

    #
    # the main alias command handler
    #
    # usage: alias [options] [name [value]]
    def cmd_alias(*args)
      # we parse args manually instead of using @@alias.opts.parse to handle special cases
      case args.length
      when 0 # print the list of current aliases
        if @aliases.length == 0
          return print_status("No aliases currently defined")
        else
          tbl = Rex::Text::Table.new(
            'Header'  => "Current Aliases",
            'Prefix'  => "\n",
            'Postfix' => "\n",
            'Columns' => [ '', 'Alias Name', 'Alias Value' ]
          )
          # add 'alias' in front of each row so that the output can be copy pasted into an rc file if desired
          @aliases.each_pair do |key,val|
            tbl << ["alias",key,val]
          end
          return print(tbl.to_s)
        end
      when 1 # display the alias if one matches this name (or help)
        return cmd_alias_help if args[0] == "-h" or args[0] == "--help"
        if @aliases.keys.include?(args[0])
          print_status("\'#{args[0]}\' is aliased to \'#{@aliases[args[0]]}\'")
        else
          print_status("\'#{args[0]}\' is not currently aliased")
        end
      else # let's see if we can assign or clear the alias
        force = false
        clear = false
        # if using -f or -c, they must be the first arg, because -f/-c may also show up in the alias
        # value so we can't do something like if args.include("-f") or delete_if etc
        # we should never have to force and clear simultaneously.
        if args[0] == "-f"
          force = true
          args.shift
        elsif args[0] == "-c"
          clear = true
          args.shift
        end
        name = args.shift
        # alias name can NEVER be certain reserved words like 'alias', add any other reserved words here
        # We prevent the user from naming the alias "alias" cuz they could end up unable to clear the aliases,
        # for example you 'alias -f set unset and then 'alias -f alias sessions', now you're screwed.  The byproduct
        # of this is that it prevents you from aliasing 'alias' to 'alias -f' etc, but that's acceptable
        reserved_words = [/^alias$/i]
        reserved_words.each do |regex|
          if name =~ regex
            print_error "You cannot use #{name} as the name for an alias, sorry"
            return false
          end
        end

        if clear
          # clear all aliases if "*"
          if name == "*"
            @aliases.keys.each do |a|
              deregister_alias(a)
            end
            print_status "Cleared all aliases"
          else # clear the named alias if it exists
            if @aliases.keys.include?(name)
              deregister_alias(name)
              print_status "Cleared alias #{name}"
            else
              print_error("#{name} is not a currently active alias")
            end
          end
          return
        end
        # smash everything that's left together
        value = args.join(" ")
        value.strip!
        # value can NEVER be certain bad words like 'rm -rf /', add any other reserved words here
        # this is basic idiot protection, not meant to be impervious to subversive intentions
        reserved_words = [/^rm +(-rf|-r +-f|-f +-r) +\/.*$/]
        reserved_words.each do |regex|
          if value =~ regex
            print_error "You cannot use #{value} as the value for an alias, sorry"
            return false
          end
        end

        is_valid_alias = is_valid_alias?(name,value)
        #print_good "Alias validity = #{is_valid_alias.to_s}"
        is_sys_cmd = Rex::FileUtils.find_full_path(name)
        is_already_alias = @aliases.keys.include?(name)
        if is_valid_alias and not is_sys_cmd and not is_already_alias
          register_alias(name, value)
        elsif force
          if not is_valid_alias
            print_status "The alias failed validation, but force is set so we allow this.  This is often the case"
            print_status "when for instance 'exploit' is being overridden but msfconsole is not currently in the"
            print_status "exploit context (an exploit is not loaded), or you are overriding a system command"
          end
          register_alias(name, value)
        else
          print_error("#{name} already exists as a system command, use -f to force override") if is_sys_cmd
          print_error("#{name} is already an alias, use -f to force override") if is_already_alias
          if not is_valid_alias and not force
            print_error("\'#{name}\' is not a permitted name or \'#{value}\' is not valid/permitted")
            print_error("It's possible the responding dispatcher isn't loaded yet, try changing to the proper context or using -f to force")
          end
        end
      end
    end

    def cmd_alias_help
      print_line "Usage: alias [options] [name [value]]"
      print_line
      print(@@alias_opts.usage())
    end

    #
    # Tab completion for the alias command
    #
    def cmd_alias_tabs(str, words)
      if words.length <= 1
        #puts "1 word or less"
        return @@alias_opts.fmt.keys + tab_complete_aliases_and_commands
      else
        #puts "more than 1 word"
        return tab_complete_aliases_and_commands
      end
    end

    private
    #
    # do everything needed to add an alias of +name+ having the value +value+
    #
    def register_alias(name, value)
      #TODO:  begin rescue?
      #TODO:  security concerns since we are using eval

      # define some class instance methods
      self.class_eval do
        # define a class instance method that will respond for the alias
        define_method "cmd_#{name}" do |*args|
          # just replace the alias w/the alias' value and run that
          driver.run_single("#{value} #{args.join(' ')}")
        end
        # define a class instance method that will tab complete the aliased command
        # we just proxy to the top-level tab complete function and let them handle it
        define_method "cmd_#{name}_tabs" do |str, words|
          # we need to repair the tab complete string/words and pass back
          # replace alias name with the root alias value
          value_words = value.split(/[\s\t\n]+/) # in case value is e.g. 'sessions -l'
          # valwords is now [sessions,-l]
          words[0] = value_words[0]
          # words[0] is now 'sessions' (was 'sue')
          value_words.shift # valwords is now ['-l']
          # insert any remaining parts of value and rebuild the line
          line = words.join(" ") + " " + value_words.join(" ") + " " + str

          #print_good "passing (#{line.strip}) back to tab_complete"
          # clear current tab_words
          driver.tab_words = []
          driver.tab_complete(line.strip)
        end
        # add a cmd_#{name}_help method
        define_method "cmd_#{name}_help" do |*args|
          driver.run_single("help #{value}")
        end
      end
      # add the alias to the list
      @aliases[name] = value
    end

    #
    # do everything required to remove an alias of name +name+
    #
    def deregister_alias(name)
      self.class_eval do
        # remove the class methods we created when the alias was registered
        remove_method("cmd_#{name}")
        remove_method("cmd_#{name}_tabs")
        remove_method("cmd_#{name}_help")
      end
      # remove the alias from the list of active aliases
      @aliases.delete(name)
    end

    #
    # Validate a proposed alias with the +name+ and having the value +value+
    #
    def is_valid_alias?(name,value)
      #print_good "Assessing validay for #{name} and #{value}"
      # we validate two things, the name and the value

      ### name
      # we don't check if this alias name exists or if it's a console command already etc as -f can override
      # that so those need to be checked externally, we pretty much just check to see if the name is sane
      name.strip!
      bad_words = [/\*/] # add any additional "bad word" regexes here
      bad_words.each do |regex|
        # don't mess around, just return false in this case, prevents wasted processing
        return false if name =~ regex
      end

      ### value
      # value is considered valid if it's a ref to a valid console cmd, a system executable, or an existing
      # alias AND isn't a "bad word"
      # Here we check for "bad words" to avoid for the value...value would have to NOT match these regexes
      # this is just basic idiot protection
      value.strip!
      bad_words = [/^msfconsole$/]
      bad_words.each do |regex|
        # don't mess around, just return false if we match
        return false if value =~ regex
      end

      # we're only gonna validate the first part of the cmd, e.g. just ls from "ls -lh"
      value = value.split(" ").first
      if @aliases.keys.include?(value)
        return true
      else
        [value, value+".exe"].each do |cmd|
          if Rex::FileUtils.find_full_path(cmd)
            return true
          end
        end
      end

      # gather all the current commands the driver's dispatcher's have & check 'em
      driver.dispatcher_stack.each do |dispatcher|
        next unless dispatcher.respond_to?(:commands)
        next if (dispatcher.commands.nil?)
        next if (dispatcher.commands.length == 0)

        if dispatcher.respond_to?("cmd_#{value.split(" ").first}")
          #print_status "Dispatcher (#{dispatcher.name}) responds to cmd_#{value.split(" ").first}"
          return true
        else
          #print_status "Dispatcher (#{dispatcher.name}) does not respond to cmd_#{value.split(" ").first}"
        end
      end

      return false
    end

    #
    # Provide tab completion list for aliases and commands
    #
    def tab_complete_aliases_and_commands
      items = []
      # gather all the current commands the driver's dispatcher's have
      driver.dispatcher_stack.each do |dispatcher|
        next unless dispatcher.respond_to?(:commands)
        next if (dispatcher.commands.nil? or dispatcher.commands.length == 0)
        items.concat(dispatcher.commands.keys)
      end
      # add all the current aliases to the list
      items.concat(@aliases.keys)
      return items
    end

  end # end AliasCommandDispatcher class

  #
  # The constructor is called when an instance of the plugin is created.  The
  # framework instance that the plugin is being associated with is passed in
  # the framework parameter.  Plugins should call the parent constructor when
  # inheriting from Msf::Plugin to ensure that the framework attribute on
  # their instance gets set.
  #
  def initialize(framework, opts)
    super

    ## Register the commands above
    add_console_dispatcher(AliasCommandDispatcher)
  end


  #
  # The cleanup routine for plugins gives them a chance to undo any actions
  # they may have done to the framework.  For instance, if a console
  # dispatcher was added, then it should be removed in the cleanup routine.
  #
  def cleanup
    # If we had previously registered a console dispatcher with the console,
    # deregister it now.
    remove_console_dispatcher('Alias')

    # we don't need to remove class methods we added because they were added to
    # AliasCommandDispatcher class
  end

  #
  # This method returns a short, friendly name for the plugin.
  #
  def name
    "alias"
  end

  #
  # This method returns a brief description of the plugin.  It should be no
  # more than 60 characters, but there are no hard limits.
  #
  def desc
    "Adds the ability to alias console commands"
  end

end ## End Plugin Class
end ## End Module
