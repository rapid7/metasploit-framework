# -*- coding: binary -*-

require 'rex/ui/text/output/buffer/stdout'

module Msf
  module Ui
    module Console
      module CommandDispatcher

        #
        # {CommandDispatcher} for commands related to background jobs in Metasploit Framework.
        #
        class Modules

          include Msf::Ui::Console::CommandDispatcher
          include Msf::Ui::Console::CommandDispatcher::Common

          # Constant for a retry timeout on using modules before they're loaded
          CMD_USE_TIMEOUT = 3

          # Constant for disclosure date formatting in search functions
          DISCLOSURE_DATE_FORMAT = "%Y-%m-%d"

          @@search_opts = Rex::Parser::Arguments.new(
            "-h" => [ false, "Help banner."]
          )

          def commands
            {
              "back"       => "Move back from the current context",
              "edit"       => "Edit the current module with the preferred editor",
              "advanced"   => "Displays advanced options for one or more modules",
              "info"       => "Displays information about one or more modules",
              "options"    => "Displays global options or for one or more modules",
              "loadpath"   => "Searches for and loads modules from a path",
              "popm"       => "Pops the latest module off the stack and makes it active",
              "pushm"      => "Pushes the active or list of modules onto the module stack",
              "previous"   => "Sets the previously loaded module as the current module",
              "reload_all" => "Reloads all modules from all defined module paths",
              "search"     => "Searches module names and descriptions",
              "show"       => "Displays modules of a given type, or all modules",
              "use"        => "Selects a module by name",
            }
          end

          #
          # Initializes the datastore cache
          #
          def initialize(driver)
            super

            @dscache = {}
            @cache_payloads = nil
            @previous_module = nil
            @module_name_stack = []
            @dangerzone_map = nil
          end

          #
          # Returns the name of the command dispatcher.
          #
          def name
            "Module"
          end

          def local_editor
            framework.datastore['LocalEditor'] || Rex::Compat.getenv('VISUAL') || Rex::Compat.getenv('EDITOR')
          end

          def cmd_edit_help
            msg = "Edit the currently active module"
            msg = "#{msg} #{local_editor ? "with #{local_editor}" : "(LocalEditor or $VISUAL/$EDITOR should be set first)"}."
            print_line "Usage: edit"
            print_line
            print_line msg
            print_line "When done editing, you must reload the module with 'reload' or 'rerun'."
            print_line
          end

          #
          # Edit the currently active module
          #
          def cmd_edit
            if active_module
              editor = local_editor
              path   = active_module.file_path

              if editor.nil?
                editor = 'vim'
                print_warning("LocalEditor or $VISUAL/$EDITOR should be set. Falling back on #{editor}.")
              end

              print_status("Launching #{editor} #{path}")
              system(editor, path)
            else
              print_error('Nothing to edit -- try using a module first.')
            end
          end

          def cmd_advanced_help
            print_line 'Usage: advanced [mod1 mod2 ...]'
            print_line
            print_line 'Queries the supplied module or modules for advanced options. If no module is given,'
            print_line 'show advanced options for the currently active module.'
            print_line
          end

          def cmd_advanced(*args)
            if args.empty?
              if (active_module)
                show_advanced_options(active_module)
                return true
              else
                print_error('No module active')
                return false
              end
            end

            args.each { |name|
              mod = framework.modules.create(name)

              if (mod == nil)
                print_error("Invalid module: #{name}")
              else
                show_advanced_options(mod)
              end
            }
          end

          def cmd_info_help
            print_line "Usage: info <module name> [mod2 mod3 ...]"
            print_line
            print_line "Options:"
            print_line "* The flag '-j' will print the data in json format"
            print_line "* The flag '-d' will show the markdown version with a browser. More info, but could be slow."
            print_line "Queries the supplied module or modules for information. If no module is given,"
            print_line "show info for the currently active module."
            print_line
          end

          #
          # Displays information about one or more module.
          #
          def cmd_info(*args)
            dump_json = false
            show_doc = false

            if args.include?('-j')
              args.delete('-j')
              dump_json = true
            end

            if args.include?('-d')
              args.delete('-d')
              show_doc = true
            end

            if (args.length == 0)
              if (active_module)
                if dump_json
                  print(Serializer::Json.dump_module(active_module) + "\n")
                elsif show_doc
                  f = Rex::Quickfile.new(["#{active_module.shortname}_doc", '.html'])
                  begin
                    print_status("Generating documentation for #{active_module.shortname}, then opening #{f.path} in a browser...")
                    Msf::Util::DocumentGenerator.spawn_module_document(active_module, f)
                  ensure
                    f.close if f
                  end
                else
                  print(Serializer::ReadableText.dump_module(active_module))
                end
                return true
              else
                cmd_info_help
                return false
              end
            elsif args.include? "-h"
              cmd_info_help
              return false
            end

            args.each { |name|
              mod = framework.modules.create(name)

              if (mod == nil)
                print_error("Invalid module: #{name}")
              elsif dump_json
                print(Serializer::Json.dump_module(mod) + "\n")
              elsif show_doc
                f = Rex::Quickfile.new(["#{mod.shortname}_doc", '.html'])
                begin
                  print_status("Generating documentation for #{mod.shortname}, then opening #{f.path} in a browser...")
                  Msf::Util::DocumentGenerator.spawn_module_document(mod, f)
                ensure
                  f.close if f
                end
              else
                print(Serializer::ReadableText.dump_module(mod))
              end
            }
          end

          def cmd_options_help
            print_line 'Usage: options [mod1 mod2 ...]'
            print_line
            print_line 'Queries the supplied module or modules for options. If no module is given,'
            print_line 'show options for the currently active module.'
            print_line
          end

          def cmd_options(*args)
            if args.empty?
              if (active_module)
                show_options(active_module)
                return true
              else
                show_global_options
                return true
              end
            end

            args.each do |name|
              mod = framework.modules.create(name)

              if (mod == nil)
                print_error("Invalid module: #{name}")
              else
                show_options(mod)
              end
            end
          end

          #
          # Tab completion for the advanced command (same as use)
          #
          # @param str (see #cmd_use_tabs)
          # @param words (see #cmd_use_tabs)

          def cmd_advanced_tabs(str, words)
            cmd_use_tabs(str, words)
          end

          #
          # Tab completion for the advanced command (same as use)
          #
          # @param str (see #cmd_use_tabs)
          # @param words (see #cmd_use_tabs)

          def cmd_info_tabs(str, words)
            cmd_use_tabs(str, words)
          end

          #
          # Tab completion for the advanced command (same as use)
          #
          # @param str (see #cmd_use_tabs)
          # @param words (see #cmd_use_tabs)

          def cmd_options_tabs(str, words)
            cmd_use_tabs(str, words)
          end

          def cmd_loadpath_help
            print_line "Usage: loadpath </path/to/modules>"
            print_line
            print_line "Loads modules from the given directory which should contain subdirectories for"
            print_line "module types, e.g. /path/to/modules/exploits"
            print_line
          end

          #
          # Adds one or more search paths.
          #
          def cmd_loadpath(*args)
            if (args.length == 0 or args.include? "-h")
              cmd_loadpath_help
              return true
            end

            totals    = {}
            overall   = 0
            curr_path = nil

            begin
              # Walk the list of supplied search paths attempting to add each one
              # along the way
              args.each { |path|
                curr_path = path

                # Load modules, but do not consult the cache
                if (counts = framework.modules.add_module_path(path))
                  counts.each_pair { |type, count|
                    totals[type] = (totals[type]) ? (totals[type] + count) : count

                    overall += count
                  }
                end
              }
            rescue NameError, RuntimeError
              log_error("Failed to add search path #{curr_path}: #{$!}")
              return true
            end

            added = "Loaded #{overall} modules:\n"

            totals.each_pair { |type, count|
              added << "    #{count} #{type}#{count != 1 ? 's' : ''}\n"
            }

            print(added)
          end

          #
          # Tab completion for the loadpath command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_loadpath_tabs(str, words)
            return [] if words.length > 1

            # This custom completion might better than Readline's... We'll leave it for now.
            #tab_complete_filenames(str,words)

            paths = []
            if (File.directory?(str))
              paths = Dir.entries(str)
              paths = paths.map { |f|
                if File.directory? File.join(str,f)
                  File.join(str,f)
                end
              }
              paths.delete_if { |f| f.nil? or File.basename(f) == '.' or File.basename(f) == '..' }
            else
              d = Dir.glob(str + "*").map { |f| f if File.directory?(f) }
              d.delete_if { |f| f.nil? or f == '.' or f == '..' }
              # If there's only one possibility, descend to the next level
              if (1 == d.length)
                paths = Dir.entries(d[0])
                paths = paths.map { |f|
                  if File.directory? File.join(d[0],f)
                    File.join(d[0],f)
                  end
                }
                paths.delete_if { |f| f.nil? or File.basename(f) == '.' or File.basename(f) == '..' }
              else
                paths = d
              end
            end
            paths.sort!
            return paths
          end

          def cmd_search_help
            print_line "Usage: search [keywords]"
            print_line
            print_line "Keywords:"
            {
              'app'      => 'Modules that are client or server attacks',
              'author'   => 'Modules written by this author',
              'bid'      => 'Modules with a matching Bugtraq ID',
              'cve'      => 'Modules with a matching CVE ID',
              'edb'      => 'Modules with a matching Exploit-DB ID',
              'name'     => 'Modules with a matching descriptive name',
              'platform' => 'Modules affecting this platform',
              'ref'      => 'Modules with a matching ref',
              'type'     => 'Modules of a specific type (exploit, auxiliary, or post)',
            }.each_pair do |keyword, description|
              print_line "  #{keyword.ljust 10}:  #{description}"
            end
            print_line
            print_line "Examples:"
            print_line "  search cve:2009 type:exploit app:client"
            print_line
          end

          #
          # Searches modules for specific keywords
          #
          def cmd_search(*args)
            match   = ''
            @@search_opts.parse(args) { |opt, idx, val|
              case opt
                when "-t"
                  print_error("Deprecated option.  Use type:#{val} instead")
                  cmd_search_help
                  return
                when "-h"
                  cmd_search_help
                  return
                else
                  match += val + " "
              end
            }

            if framework.db
              if framework.db.migrated && framework.db.modules_cached
                search_modules_sql(match)
                return
              else
                print_warning("Module database cache not built yet, using slow search")
              end
            else
              print_warning("Database not connected, using slow search")
            end

            tbl = generate_module_table("Matching Modules")
            [
              framework.exploits,
              framework.auxiliary,
              framework.post,
              framework.payloads,
              framework.nops,
              framework.encoders
            ].each do |mset|
              mset.each do |m|
                o = mset.create(m[0]) rescue nil

                # Expected if modules are loaded without the right pre-requirements
                next if not o

                if not o.search_filter(match)
                  tbl << [ o.fullname, o.disclosure_date.nil? ? "" : o.disclosure_date.strftime(DISCLOSURE_DATE_FORMAT), o.rank_to_s, o.name ]
                end
              end
            end
            print_line(tbl.to_s)

          end

          # Prints table of modules matching the search_string.
          #
          # @param (see Msf::DBManager#search_modules)
          # @return [void]
          def search_modules_sql(search_string)
            tbl = generate_module_table("Matching Modules")
            framework.db.search_modules(search_string).each do |o|
              tbl << [ o.fullname, o.disclosure_date.nil? ? "" : o.disclosure_date.strftime(DISCLOSURE_DATE_FORMAT), RankingName[o.rank].to_s, o.name ]
            end
            print_line(tbl.to_s)
          end

          #
          # Tab completion for the search command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_search_tabs(str, words)
            if words.length == 1
              return @@search_opts.fmt.keys
            end

            case (words[-1])
              when "-r"
                return RankingName.sort.map{|r| r[1]}
              when "-t"
                return %w{auxiliary encoder exploit nop payload post}
            end

            []
          end

          def cmd_show_help
            global_opts = %w{all encoders nops exploits payloads auxiliary plugins info options}
            print_status("Valid parameters for the \"show\" command are: #{global_opts.join(", ")}")

            module_opts = %w{ missing advanced evasion targets actions }
            print_status("Additional module-specific parameters are: #{module_opts.join(", ")}")
          end

          #
          # Displays the list of modules based on their type, or all modules if
          # no type is provided.
          #
          def cmd_show(*args)
            mod = self.active_module

            args << "all" if (args.length == 0)

            args.each { |type|
              case type
                when '-h'
                  cmd_show_help
                when 'all'
                  show_encoders
                  show_nops
                  show_exploits
                  show_payloads
                  show_auxiliary
                  show_post
                  show_plugins
                when 'encoders'
                  show_encoders
                when 'nops'
                  show_nops
                when 'exploits'
                  show_exploits
                when 'payloads'
                  show_payloads
                when 'auxiliary'
                  show_auxiliary
                when 'post'
                  show_post
                when 'info'
                  cmd_info(*args[1, args.length])
                when 'options'
                  if (mod)
                    show_options(mod)
                  else
                    show_global_options
                  end
                when 'missing'
                  if (mod)
                    show_missing(mod)
                  else
                    print_error("No module selected.")
                  end
                when 'advanced'
                  if (mod)
                    show_advanced_options(mod)
                  else
                    print_error("No module selected.")
                  end
                when 'evasion'
                  if (mod)
                    show_evasion_options(mod)
                  else
                    print_error("No module selected.")
                  end
                when 'sessions'
                  if (active_module and active_module.respond_to?(:compatible_sessions))
                    sessions = active_module.compatible_sessions
                  else
                    sessions = framework.sessions.keys.sort
                  end
                  print_line
                  print(Serializer::ReadableText.dump_sessions(framework, :session_ids => sessions))
                  print_line
                when "plugins"
                  show_plugins
                when "targets"
                  if (mod and mod.exploit?)
                    show_targets(mod)
                  else
                    print_error("No exploit module selected.")
                  end
                when "actions"
                  if mod && mod.kind_of?(Msf::Module::HasActions)
                    show_actions(mod)
                  else
                    print_error("No module with actions selected.")
                  end

                else
                  print_error("Invalid parameter \"#{type}\", use \"show -h\" for more information")
              end
            }
          end

          #
          # Tab completion for the show command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_show_tabs(str, words)
            return [] if words.length > 1

            res = %w{all encoders nops exploits payloads auxiliary post plugins options}
            if (active_module)
              res.concat %w{missing advanced evasion targets actions info}
              if (active_module.respond_to? :compatible_sessions)
                res << "sessions"
              end
            end
            return res
          end

          def cmd_use_help
            print_line "Usage: use module_name"
            print_line
            print_line "The use command is used to interact with a module of a given name."
            print_line
          end

          #
          # Uses a module.
          #
          def cmd_use(*args)
            if (args.length == 0)
              cmd_use_help
              return false
            end

            # Divert logic for dangerzone mode
            args = dangerzone_codename_to_module(args)

            # Try to create an instance of the supplied module name
            mod_name = args[0]

            # Ensure we have a reference name and not a path
            if mod_name.start_with?('modules/', '/')
              mod_name.sub!(/^(?:modules)?\//, '')
            end
            if mod_name.end_with?('.', '.r', '.rb')
              mod_name.sub!(/\.(?:rb?)?$/, '')
            end

            begin
              mod = framework.modules.create(mod_name)
              unless mod
                # Try one more time; see #4549
                sleep CMD_USE_TIMEOUT
                mod = framework.modules.create(mod_name)
                unless mod
                  print_error("Failed to load module: #{mod_name}")
                  return false
                end
              end
            rescue Rex::AmbiguousArgumentError => info
              print_error(info.to_s)
            rescue NameError => info
              log_error("The supplied module name is ambiguous: #{$!}.")
            end

            return false if (mod == nil)

            # Enstack the command dispatcher for this module type
            dispatcher = nil

            case mod.type
              when Msf::MODULE_ENCODER
                dispatcher = Msf::Ui::Console::CommandDispatcher::Encoder
              when Msf::MODULE_EXPLOIT
                dispatcher = Msf::Ui::Console::CommandDispatcher::Exploit
              when Msf::MODULE_NOP
                dispatcher = Msf::Ui::Console::CommandDispatcher::Nop
              when Msf::MODULE_PAYLOAD
                dispatcher = Msf::Ui::Console::CommandDispatcher::Payload
              when Msf::MODULE_AUX
                dispatcher = Msf::Ui::Console::CommandDispatcher::Auxiliary
              when Msf::MODULE_POST
                dispatcher = Msf::Ui::Console::CommandDispatcher::Post
              else
                print_error("Unsupported module type: #{mod.type}")
                return false
            end

            # If there's currently an active module, enqueque it and go back
            if (active_module)
              @previous_module = active_module
              cmd_back()
            end

            if (dispatcher != nil)
              driver.enstack_dispatcher(dispatcher)
            end

            # Update the active module
            self.active_module = mod

            # If a datastore cache exists for this module, then load it up
            if @dscache[active_module.fullname]
              active_module.datastore.update(@dscache[active_module.fullname])
            end

            @cache_payloads = nil
            mod.init_ui(driver.input, driver.output)

            # Update the command prompt
            prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
            prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
            driver.update_prompt("#{prompt} #{mod.type}(%bld%red#{mod.shortname}%clr) ", prompt_char, true)
          end

          #
          # Command to take to the previously active module
          #
          def cmd_previous()
            if @previous_module
              self.cmd_use(@previous_module.fullname)
            else
              print_error("There isn't a previous module at the moment")
            end
          end

          #
          # Help for the 'previous' command
          #
          def cmd_previous_help
            print_line "Usage: previous"
            print_line
            print_line "Set the previously loaded module as the current module"
            print_line
          end

          #
          # Command to enqueque a module on the module stack
          #
          def cmd_pushm(*args)
            # could check if each argument is a valid module, but for now let them hang themselves
            if args.count > 0
              args.each do |arg|
                @module_name_stack.push(arg)
                # Note new modules are appended to the array and are only module (full)names
              end
            else #then just push the active module
              if active_module
                #print_status "Pushing the active module"
                @module_name_stack.push(active_module.fullname)
              else
                print_error("There isn't an active module and you didn't specify a module to push")
                return self.cmd_pushm_help
              end
            end
          end

          #
          # Tab completion for the pushm command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_pushm_tabs(str, words)
            tab_complete_module(str, words)
          end

          #
          # Help for the 'pushm' command
          #
          def cmd_pushm_help
            print_line "Usage: pushm [module1 [,module2, module3...]]"
            print_line
            print_line "push current active module or specified modules onto the module stack"
            print_line
          end

          #
          # Command to dequeque a module from the module stack
          #
          def cmd_popm(*args)
            if (args.count > 1 or not args[0].respond_to?("to_i"))
              return self.cmd_popm_help
            elsif args.count == 1
              # then pop 'n' items off the stack, but don't change the active module
              if args[0].to_i >= @module_name_stack.count
                # in case they pass in a number >= the length of @module_name_stack
                @module_name_stack = []
                print_status("The module stack is empty")
              else
                @module_name_stack.pop[args[0]]
              end
            else #then just pop the array and make that the active module
              pop = @module_name_stack.pop
              if pop
                return self.cmd_use(pop)
              else
                print_error("There isn't anything to pop, the module stack is empty")
              end
            end
          end

          #
          # Help for the 'popm' command
          #
          def cmd_popm_help
            print_line "Usage: popm [n]"
            print_line
            print_line "pop the latest module off of the module stack and make it the active module"
            print_line "or pop n modules off the stack, but don't change the active module"
            print_line
          end

          #
          # Tab completion for the use command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completd

          def cmd_use_tabs(str, words)
            return [] if words.length > 1

            tab_complete_module(str, words)
          end

          def cmd_reload_all_help
            print_line "Usage: reload_all"
            print_line
            print_line "Reload all modules from all configured module paths.  This may take awhile."
            print_line "See also: loadpath"
            print_line
          end

          #
          # Reload all module paths that we are aware of
          #
          def cmd_reload_all(*args)
            if args.length > 0
              cmd_reload_all_help
              return
            end
            print_status("Reloading modules from all module paths...")
            framework.modules.reload_modules

            # Check for modules that failed to load
            if framework.modules.module_load_error_by_path.length > 0
              print_error("WARNING! The following modules could not be loaded!")

              framework.modules.module_load_error_by_path.each do |path, error|
                print_error("\t#{path}: #{error}")
              end
            end

            if framework.modules.module_load_warnings.length > 0
              print_warning("The following modules were loaded with warnings:")
              framework.modules.module_load_warnings.each do |path, error|
                print_warning("\t#{path}: #{error}")
              end
            end

            self.driver.run_single("banner")
          end

          def cmd_back_help
            print_line "Usage: back"
            print_line
            print_line "Return to the global dispatcher context"
            print_line
          end

          #
          # Pop the current dispatcher stack context, assuming it isn't pointed at
          # the core or database backend stack context.
          #
          def cmd_back(*args)
            if (driver.dispatcher_stack.size > 1 and
              driver.current_dispatcher.name != 'Core' and
              driver.current_dispatcher.name != 'Database Backend')
              # Reset the active module if we have one
              if (active_module)

                # Do NOT reset the UI anymore
                # active_module.reset_ui

                # Save the module's datastore so that we can load it later
                # if the module is used again
                @dscache[active_module.fullname] = active_module.datastore.dup

                self.active_module = nil
              end

              # Destack the current dispatcher
              driver.destack_dispatcher

              # Restore the prompt
              prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
              prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
              driver.update_prompt("#{prompt} ", prompt_char, true)
            end
          end

          #
          # Tab complete module names
          #
          def tab_complete_module(str, words)
            res = []
            framework.modules.module_types.each do |mtyp|
              mset = framework.modules.module_names(mtyp)
              mset.each do |mref|
                res << mtyp + '/' + mref
              end
            end

            return dangerzone_modules_to_codenames(res.sort) if dangerzone_active?
            return res.sort
          end

          #
          # Convert squirrel names back to regular module names
          #
          def dangerzone_codename_to_module(args)
            return args unless dangerzone_active? && args.length > 0 && args[0].length > 0
            return args unless args[0] =~ /^[A-Z]/
            args[0] = dangerzone_codename_to_module_name(args[0])
            args
          end

          #
          # Determine if dangerzone mode is active via date or environment variable
          #
          def dangerzone_active?
            active = Time.now.strftime("%m%d") == "0401" || Rex::Compat.getenv('DANGERZONE').to_i > 0
            if active && @dangerzone_map.nil?
              dangerzone_build_map
            end
            active
          end

          #
          # Convert module names to squirrel names
          #
          def dangerzone_modules_to_codenames(names)
            (names + @dangerzone_map.keys.grep(/^[A-Z]+/)).sort
          end

          def dangerzone_codename_to_module_name(cname)
            @dangerzone_map[cname] || cname
          end

          def dangerzone_module_name_to_codename(mname)
            @dangerzone_map[mname] || mname
          end

          def dangerzone_build_map
            return unless @dangerzone_map.nil?

            @dangerzone_map = {}

            res = []
            %W{exploit auxiliary}.each do |mtyp|
              mset = framework.modules.module_names(mtyp)
              mset.each do |mref|
                res << mtyp + '/' + mref
              end
            end

            words_a = ::File.readlines(::File.join(
              ::Msf::Config.data_directory, "wordlists", "dangerzone_a.txt"
              )).map{|line| line.strip.upcase}

            words_b = ::File.readlines(::File.join(
              ::Msf::Config.data_directory, "wordlists", "dangerzone_b.txt"
              )).map{|line| line.strip.upcase}

            aidx = -1
            bidx = -1

            res.sort.each do |mname|
              word_a = words_a[ (aidx += 1) % words_a.length ]
              word_b = words_b[ (bidx += 1) % words_b.length ]
              cname = word_a + word_b

              while @dangerzone_map[cname]
                aidx += 1
                word_a = words_a[ (aidx += 1) % words_a.length ]
                cname = word_a + word_b
              end

              @dangerzone_map[mname] = cname
              @dangerzone_map[cname] = mname
            end
          end

          #
          # Module list enumeration
          #

          def show_encoders(regex = nil, minrank = nil, opts = nil) # :nodoc:
            # If an active module has been selected and it's an exploit, get the
            # list of compatible encoders and display them
            if (active_module and active_module.exploit? == true)
              show_module_set("Compatible Encoders", active_module.compatible_encoders, regex, minrank, opts)
            else
              show_module_set("Encoders", framework.encoders, regex, minrank, opts)
            end
          end

          def show_nops(regex = nil, minrank = nil, opts = nil) # :nodoc:
            show_module_set("NOP Generators", framework.nops, regex, minrank, opts)
          end

          def show_exploits(regex = nil, minrank = nil, opts = nil) # :nodoc:
            show_module_set("Exploits", framework.exploits, regex, minrank, opts)
          end

          def show_payloads(regex = nil, minrank = nil, opts = nil) # :nodoc:
            # If an active module has been selected and it's an exploit, get the
            # list of compatible payloads and display them
            if (active_module and active_module.exploit? == true)
              show_module_set("Compatible Payloads", active_module.compatible_payloads, regex, minrank, opts)
            else
              show_module_set("Payloads", framework.payloads, regex, minrank, opts)
            end
          end

          def show_auxiliary(regex = nil, minrank = nil, opts = nil) # :nodoc:
            show_module_set("Auxiliary", framework.auxiliary, regex, minrank, opts)
          end

          def show_post(regex = nil, minrank = nil, opts = nil) # :nodoc:
            show_module_set("Post", framework.post, regex, minrank, opts)
          end

          def show_missing(mod) # :nodoc:
            mod_opt = Serializer::ReadableText.dump_options(mod, '   ', true)
            print("\nModule options (#{mod.fullname}):\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

            # If it's an exploit and a payload is defined, create it and
            # display the payload's options
            if (mod.exploit? and mod.datastore['PAYLOAD'])
              p = framework.payloads.create(mod.datastore['PAYLOAD'])

              if (!p)
                print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
                return
              end

              p.share_datastore(mod.datastore)

              if (p)
                p_opt = Serializer::ReadableText.dump_options(p, '   ', true)
                print("\nPayload options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
              end
            end
          end

          def show_global_options
            columns = [ 'Option', 'Current Setting', 'Description' ]
            tbl = Table.new(
              Table::Style::Default,
              'Header'  => 'Global Options:',
              'Prefix'  => "\n",
              'Postfix' => "\n",
              'Columns' => columns
            )
            [
              [ 'ConsoleLogging', framework.datastore['ConsoleLogging'] || "false", 'Log all console input and output' ],
              [ 'LogLevel', framework.datastore['LogLevel'] || "0", 'Verbosity of logs (default 0, max 3)' ],
              [ 'MinimumRank', framework.datastore['MinimumRank'] || "0", 'The minimum rank of exploits that will run without explicit confirmation' ],
              [ 'SessionLogging', framework.datastore['SessionLogging'] || "false", 'Log all input and output for sessions' ],
              [ 'TimestampOutput', framework.datastore['TimestampOutput'] || "false", 'Prefix all console output with a timestamp' ],
              [ 'Prompt', framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt.to_s.gsub(/%.../,"") , "The prompt string" ],
              [ 'PromptChar', framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar.to_s.gsub(/%.../,""), "The prompt character" ],
              [ 'PromptTimeFormat', framework.datastore['PromptTimeFormat'] || Time::DATE_FORMATS[:db].to_s, 'Format for timestamp escapes in prompts' ],
            ].each { |r| tbl << r }

            print(tbl.to_s)
          end

          def show_targets(mod) # :nodoc:
            mod_targs = Serializer::ReadableText.dump_exploit_targets(mod, '   ')
            print("\nExploit targets:\n\n#{mod_targs}\n") if (mod_targs and mod_targs.length > 0)
          end

          def show_actions(mod) # :nodoc:
            mod_actions = Serializer::ReadableText.dump_module_actions(mod, '   ')
            print("\n#{mod.type.capitalize} actions:\n\n#{mod_actions}\n") if (mod_actions and mod_actions.length > 0)
          end

          def show_advanced_options(mod) # :nodoc:
            mod_opt = Serializer::ReadableText.dump_advanced_options(mod, '   ')
            print("\nModule advanced options (#{mod.fullname}):\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

            # If it's an exploit and a payload is defined, create it and
            # display the payload's options
            if (mod.exploit? and mod.datastore['PAYLOAD'])
              p = framework.payloads.create(mod.datastore['PAYLOAD'])

              if (!p)
                print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
                return
              end

              p.share_datastore(mod.datastore)

              if (p)
                p_opt = Serializer::ReadableText.dump_advanced_options(p, '   ')
                print("\nPayload advanced options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
              end
            end
          end

          def show_evasion_options(mod) # :nodoc:
            mod_opt = Serializer::ReadableText.dump_evasion_options(mod, '   ')
            print("\nModule evasion options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

            # If it's an exploit and a payload is defined, create it and
            # display the payload's options
            if (mod.exploit? and mod.datastore['PAYLOAD'])
              p = framework.payloads.create(mod.datastore['PAYLOAD'])

              if (!p)
                print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
                return
              end

              p.share_datastore(mod.datastore)

              if (p)
                p_opt = Serializer::ReadableText.dump_evasion_options(p, '   ')
                print("\nPayload evasion options (#{mod.datastore['PAYLOAD']}):\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
              end
            end
          end

          def show_plugins # :nodoc:
            tbl = Table.new(
              Table::Style::Default,
              'Header'  => 'Plugins',
              'Prefix'  => "\n",
              'Postfix' => "\n",
              'Columns' => [ 'Name', 'Description' ]
            )

            framework.plugins.each { |plugin|
              tbl << [ plugin.name, plugin.desc ]
            }

            print(tbl.to_s)
          end

          def show_module_set(type, module_set, regex = nil, minrank = nil, opts = nil) # :nodoc:
            tbl = generate_module_table(type)
            module_set.sort.each { |refname, mod|
              o = nil

              begin
                o = mod.new
              rescue ::Exception
              end
              next if not o

              # handle a search string, search deep
              if (
              not regex or
                o.name.match(regex) or
                o.description.match(regex) or
                o.refname.match(regex) or
                o.references.map{|x| [x.ctx_id + '-' + x.ctx_val, x.to_s]}.join(' ').match(regex) or
                o.author.to_s.match(regex)
              )
                if (not minrank or minrank <= o.rank)
                  show = true
                  if opts
                    mod_opt_keys = o.options.keys.map { |x| x.downcase }

                    opts.each do |opt,val|
                      if !mod_opt_keys.include?(opt.downcase) || (val != nil && o.datastore[opt] != val)
                        show = false
                      end
                    end
                  end
                  if (opts == nil or show == true)
                    tbl << [ refname, o.disclosure_date.nil? ? "" : o.disclosure_date.strftime(DISCLOSURE_DATE_FORMAT), o.rank_to_s, o.name ]
                  end
                end
              end
            }

            print(tbl.to_s)
          end

          def generate_module_table(type) # :nodoc:
            Table.new(
              Table::Style::Default,
              'Header'  => type,
              'Prefix'  => "\n",
              'Postfix' => "\n",
              'Columns' => [ 'Name', 'Disclosure Date', 'Rank', 'Description' ]
            )
          end

        end
      end
    end
  end
end
