# -*- coding: binary -*-


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

          include Rex::Text::Color

          @@search_opts = Rex::Parser::Arguments.new(
            ['-h', '--help']            => [false, 'Help banner'],
            ['-I', '--ignore']          => [false, 'Ignore the command if the only match has the same name as the search'],
            ['-o', '--output']          => [true,  'Send output to a file in csv format', '<filename>'],
            ['-S', '--filter']          => [true,  'Regex pattern used to filter search results', '<filter>'],
            ['-u', '--use']             => [false, 'Use module if there is one result'],
            ['-s', '--sort-ascending']  => [true, 'Sort search results by the specified column in ascending order', '<column>'],
            ['-r', '--sort-descending'] => [true, 'Reverse the order of search results to descending order', '<column>']
          )

          @@favorite_opts = Rex::Parser::Arguments.new(
            '-h' => [false, 'Help banner'],
            '-c' => [false, 'Clear the contents of the favorite modules file'],
            '-d' => [false, 'Delete module(s) or the current active module from the favorite modules file'],
            '-l' => [false, 'Print the list of favorite modules (alias for `show favorites`)']
          )

          @@favorites_opts = Rex::Parser::Arguments.new(
            '-h' => [false, 'Help banner']
          )

          def commands
            {
              "back"       => "Move back from the current context",
              "advanced"   => "Displays advanced options for one or more modules",
              "info"       => "Displays information about one or more modules",
              "options"    => "Displays global options or for one or more modules",
              "loadpath"   => "Searches for and loads modules from a path",
              "popm"       => "Pops the latest module off the stack and makes it active",
              "pushm"      => "Pushes the active or list of modules onto the module stack",
              "listm"      => "List the module stack",
              "clearm"     => "Clear the module stack",
              "previous"   => "Sets the previously loaded module as the current module",
              "reload_all" => "Reloads all modules from all defined module paths",
              "search"     => "Searches module names and descriptions",
              "show"       => "Displays modules of a given type, or all modules",
              "use"        => "Interact with a module by name or search term/index",
              "favorite"   => "Add module(s) to the list of favorite modules",
              "favorites"  => "Print the list of favorite modules (alias for `show favorites`)"
            }
          end

          #
          # Initializes the datastore cache
          #
          def initialize(driver)
            super

            @dscache = {}
            @previous_module = nil
            @module_name_stack = []
            # Array of individual modules that have been searched for
            @module_search_results = []
            # Module search results, with additional metadata on what to do if the module is interacted with
            @module_search_results_with_usage_metadata = []
            @@payload_show_results = []
            @dangerzone_map = nil
          end

          #
          # Returns the name of the command dispatcher.
          #
          def name
            "Module"
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

          def print_module_info(mod, dump_json: false, show_doc: false)
            if dump_json
              print(Serializer::Json.dump_module(mod) + "\n")
            elsif show_doc
              f = Tempfile.new(["#{mod.shortname}_doc", '.html'])
              begin
                print_status("Generating documentation for #{mod.shortname}, then opening #{f.path} in a browser...")
                Msf::Util::DocumentGenerator.spawn_module_document(mod, f)
              ensure
                f.close if f
              end
            else
              print(Serializer::ReadableText.dump_module(mod))
              print("\nView the full module info with the #{Msf::Ui::Tip.highlight('info -d')} command.\n\n")
            end
          end

          # Handles the index selection formatting
          def print_module_search_results_usage
            last_mod_with_usage_metadata = @module_search_results_with_usage_metadata.last
            index_usage = "use #{@module_search_results_with_usage_metadata.length - 1}"
            index_info = "info #{@module_search_results_with_usage_metadata.length - 1}"
            name_usage = "use #{last_mod_with_usage_metadata[:mod].fullname}"

            additional_usage_message = ""
            additional_usage_example = (last_mod_with_usage_metadata[:datastore] || {}).first
            if framework.features.enabled?(Msf::FeatureManager::HIERARCHICAL_SEARCH_TABLE) && additional_usage_example
              key, value = additional_usage_example
              additional_usage_message = "\nAfter interacting with a module you can manually set a #{key} with %grnset #{key} '#{value}'%clr"
            end
            print("Interact with a module by name or index. For example %grn#{index_info}%clr, %grn#{index_usage}%clr or %grn#{name_usage}%clr#{additional_usage_message}\n\n")
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
              if active_module
                print_module_info(active_module, dump_json: dump_json, show_doc: show_doc)
                return true
              else
                cmd_info_help
                return false
              end
            elsif args.include? '-h'
              cmd_info_help
              return false
            end

            args.each do |arg|
              mod_name = arg

              additional_datastore_values = nil

              # Use a module by search index
              index_from_list(@module_search_results_with_usage_metadata, mod_name) do |result|
                mod = result&.[](:mod)
                next unless mod && mod.respond_to?(:fullname)

                # Module cache object
                mod_name = mod.fullname
                additional_datastore_values = result[:datastore]
              end

              # Ensure we have a reference name and not a path
              name = trim_path(mod_name, 'modules')

              # Creates an instance of the module
              mod = framework.modules.create(name)

              # If any additional datastore values were provided, set these values
              mod.datastore.update(additional_datastore_values) unless additional_datastore_values.nil?

              if mod.nil?
                print_error("Invalid module: #{name}")
              else
                print_module_info(mod, dump_json: dump_json, show_doc: show_doc)
              end
            end
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

            totals.sort_by { |type, _count| type }.each { |type, count|
              added << "    #{count} #{type} modules\n"
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
            print_line "Usage: search [<options>] [<keywords>:<value>]"
            print_line
            print_line "Prepending a value with '-' will exclude any matching results."
            print_line "If no options or keywords are provided, cached results are displayed."
            print_line
            print @@search_opts.usage
            print_line
            print_line "Keywords:"
            {
              'action'      => 'Modules with a matching action name or description',
              'adapter'     => 'Modules with a matching adapter reference name',
              'aka'         => 'Modules with a matching AKA (also-known-as) name',
              'arch'        => 'Modules affecting this architecture',
              'att&ck'      => 'Modules with a matching MITRE ATT&CK ID or reference',
              'author'      => 'Modules written by this author',
              'bid'         => 'Modules with a matching Bugtraq ID',
              'check'       => 'Modules that support the \'check\' method',
              'cve'         => 'Modules with a matching CVE ID',
              'date'        => 'Modules with a matching disclosure date',
              'description' => 'Modules with a matching description',
              'edb'         => 'Modules with a matching Exploit-DB ID',
              'fullname'    => 'Modules with a matching full name',
              'mod_time'    => 'Modules with a matching modification date',
              'name'        => 'Modules with a matching descriptive name',
              'osvdb'       => 'Modules with a matching OSVDB ID',
              'path'        => 'Modules with a matching path',
              'platform'    => 'Modules affecting this platform',
              'port'        => 'Modules with a matching port',
              'rank'        => 'Modules with a matching rank (Can be descriptive (ex: \'good\') or numeric with comparison operators (ex: \'gte400\'))',
              'ref'         => 'Modules with a matching ref',
              'reference'   => 'Modules with a matching reference',
              'session_type' => 'Modules with a matching session type (SMB, MySQL, Meterpreter, etc)',
              'stage'       => 'Modules with a matching stage reference name',
              'stager'      => 'Modules with a matching stager reference name',
              'target'      => 'Modules affecting this target',
              'type'        => 'Modules of a specific type (exploit, payload, auxiliary, encoder, evasion, post, or nop)',
            }.each_pair do |keyword, description|
              print_line "  #{keyword.ljust 17}:  #{description}"
            end
            print_line
            print_line "Supported search columns:"
            {
              'rank'                 => 'Sort modules by their exploitability rank',
              'date'                 => 'Sort modules by their disclosure date. Alias for disclosure_date',
              'disclosure_date'      => 'Sort modules by their disclosure date',
              'name'                 => 'Sort modules by their name',
              'type'                 => 'Sort modules by their type',
              'check'                => 'Sort modules by whether or not they have a check method',
              'action'                => 'Sort modules by whether or not they have actions',
            }.each_pair do |keyword, description|
              print_line "  #{keyword.ljust 17}:  #{description}"
            end
            print_line
            print_line "Examples:"
            print_line "  search cve:2009 type:exploit"
            print_line "  search cve:2009 type:exploit platform:-linux"
            print_line "  search cve:2009 -s name"
            print_line "  search type:exploit -s type -r"
            print_line "  search att&ck:T1059"
            print_line
          end

          #
          # Searches modules for specific keywords
          #
          def cmd_search(*args)
            match        = ''
            row_filter  = nil
            output_file  = nil
            cached       = false
            use          = false
            count        = -1
            search_terms = []
            sort_attribute  = 'name'
            valid_sort_attributes = ['action', 'rank','disclosure_date','name','date','type','check']
            reverse_sort = false
            ignore_use_exact_match = false

            @@search_opts.parse(args) do |opt, idx, val|
              case opt
              when '-S'
                row_filter = val
              when '-h'
                cmd_search_help
                return false
              when '-o'
                output_file = val
              when '-u'
                use = true
              when '-I'
                ignore_use_exact_match = true
              when '-s'
                sort_attribute = val
              when '-r'
                reverse_sort = true
              else
                match += val + ' '
              end
            end

            if args.empty?
              if @module_search_results_with_usage_metadata.empty?
                cmd_search_help
                return false
              end

              cached = true
            end

            if sort_attribute && !valid_sort_attributes.include?(sort_attribute)
              print_error("Supported options for the -s flag are: #{valid_sort_attributes}")
              return false
            end

            begin
              if cached
                print_status('Displaying cached results')
              else
                search_params = Msf::Modules::Metadata::Search.parse_search_string(match)
                @module_search_results = Msf::Modules::Metadata::Cache.instance.find(search_params)

                @module_search_results.sort_by! do |module_metadata|
                  if sort_attribute == 'action'
                    module_metadata.actions&.any? ? 0 : 1
                  elsif sort_attribute == 'check'
                    module_metadata.check ? 0 : 1
                  elsif sort_attribute == 'disclosure_date' || sort_attribute == 'date'
                    # Not all modules have disclosure_date, i.e. multi/handler
                    module_metadata.disclosure_date || Time.utc(0)
                  else
                    module_metadata.send(sort_attribute)
                  end
                end

                if reverse_sort
                  @module_search_results.reverse!
                end
              end

              if @module_search_results.empty?
                print_error('No results from search')
                return false
              end

              if ignore_use_exact_match && @module_search_results.length == 1 &&
                @module_search_results.first.fullname == match.strip
                return false
              end

              if !search_params.nil? && !search_params['text'].nil?
                search_params['text'][0].each do |t|
                  search_terms << t
                end
              end

              # Generate the table used to display matches
              tbl = generate_module_table('Matching Modules', search_terms, row_filter)

              @module_search_results_with_usage_metadata = []
              @module_search_results.each do |m|
                @module_search_results_with_usage_metadata << { mod: m }
                count += 1
                tbl << [
                  count,
                  "#{m.fullname}",
                  m.disclosure_date.nil? ? '' : m.disclosure_date.strftime("%Y-%m-%d"),
                  m.rank,
                  m.check ? 'Yes' : 'No',
                  m.name,
                ]

                if framework.features.enabled?(Msf::FeatureManager::HIERARCHICAL_SEARCH_TABLE)
                  total_children_rows = (m.actions&.length || 0) + (m.targets&.length || 0) + (m.notes&.[]('AKA')&.length || 0)
                  show_child_items = total_children_rows > 1
                  next unless show_child_items

                  indent = "  \\_ "
                  # Note: We still use visual indicators for blank values as it's easier to read
                  # We can't always use a generic formatter/styler, as it would be applied to the 'parent' rows too
                  blank_value = '.'
                  if (m.actions&.length || 0) > 1
                    m.actions.each do |action|
                      @module_search_results_with_usage_metadata << { mod: m, datastore: { 'ACTION' => action['name'] } }
                      count += 1
                      tbl << [
                        count,
                        "#{indent}action: #{action['name']}",
                        blank_value,
                        blank_value,
                        blank_value,
                        action['description'],
                      ]
                    end
                  end

                  if (m.targets&.length || 0) > 1
                    m.targets.each do |target|
                      @module_search_results_with_usage_metadata << { mod: m, datastore: { 'TARGET' => target } }
                      count += 1
                      tbl << [
                        count,
                        "#{indent}target: #{target}",
                        blank_value,
                        blank_value,
                        blank_value,
                        blank_value
                      ]
                    end
                  end

                  if (m.notes&.[]('AKA')&.length || 0) > 1
                    m.notes['AKA'].each do |aka|
                      @module_search_results_with_usage_metadata << { mod: m }
                      count += 1
                      tbl << [
                        count,
                        "#{indent}AKA: #{aka}",
                        blank_value,
                        blank_value,
                        blank_value,
                        blank_value
                      ]
                    end
                  end
                end
              end
            rescue ArgumentError
              print_error("Invalid argument(s)\n")
              cmd_search_help
              return false
            end

            if output_file
              print_status("Wrote search results to #{output_file}")
              ::File.open(output_file, "wb") { |ofd|
                ofd.write(tbl.to_csv)
              }
              return true
            end

            print_line(tbl.to_s)
            print_module_search_results_usage

            if @module_search_results.length == 1 && use
              used_module = @module_search_results_with_usage_metadata.first[:mod].fullname
              print_status("Using #{used_module}") if used_module
              cmd_use(used_module, true)
            end

            true
          end

          #
          # Tab completion for the search command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_search_tabs(str, words)
            if words.length == 1
              return @@search_opts.option_keys
            end

            []
          end

          def cmd_show_help
            global_opts = %w{all encoders nops exploits payloads auxiliary post plugins info options favorites}
            print_status("Valid parameters for the \"show\" command are: #{global_opts.join(", ")}")

            module_opts = %w{ missing advanced evasion targets actions }
            print_status("Additional module-specific parameters are: #{module_opts.join(", ")}")
          end

          #
          # Displays the list of modules based on their type, or all modules if
          # no type is provided.
          #
          def cmd_show(*args)
            if args.empty?
              print_error("Argument required\n")
              cmd_show_help
              return
            end

            mod = self.active_module

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
                when 'favorites'
                  show_favorites
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
                    show_evasion
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
                  if (mod and (mod.exploit? or mod.evasion?))
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

            res = %w{all encoders nops exploits payloads auxiliary post plugins options favorites}
            if (active_module)
              res.concat %w{missing advanced evasion targets actions info}
              if (active_module.respond_to? :compatible_sessions)
                res << "sessions"
              end
            end
            return res
          end

          def cmd_use_help
            print_line 'Usage: use <name|term|index>'
            print_line
            print_line 'Interact with a module by name or search term/index.'
            print_line 'If a module name is not found, it will be treated as a search term.'
            print_line 'An index from the previous search results can be selected if desired.'
            print_line
            print_line 'Examples:'
            print_line '  use exploit/windows/smb/ms17_010_eternalblue'
            print_line
            print_line '  use eternalblue'
            print_line '  use <name|index>'
            print_line
            print_line '  search eternalblue'
            print_line '  use <name|index>'
            print_line
            print_april_fools_module_use
          end

          #
          # Uses a module.
          #
          def cmd_use(*args)
            if args.length == 0 || args.first == '-h'
              cmd_use_help
              return false
            end

            # Divert logic for dangerzone mode
            args = dangerzone_codename_to_module(args)

            # Try to create an instance of the supplied module name
            mod_name = args[0]

            additional_datastore_values = nil

            # Use a module by search index
            index_from_list(@module_search_results_with_usage_metadata, mod_name) do |result|
              mod = result&.[](:mod)
              unless mod && mod.respond_to?(:fullname)
                print_error("Invalid module index: #{mod_name}")
                return false
              end

              # Module cache object from @module_search_results_with_usage_metadata
              mod_name = mod.fullname
              additional_datastore_values = result[:datastore]
            end

            # See if the supplied module name has already been resolved
            mod_resolved = args[1] == true ? true : false

            # Ensure we have a reference name and not a path
            mod_name = trim_path(mod_name, "modules")

            begin
              mod = framework.modules.create(mod_name)

              unless mod
                # Checks to see if we have any load_errors for the current module.
                # and if so, returns them to the user.
                load_error = framework.modules.load_error_by_name(mod_name)
                if load_error
                  print_error("Failed to load module: #{load_error}")
                  return false
                end
                unless mod_resolved
                  elog("Module #{mod_name} not found, and no loading errors found. If you're using a custom module" \
                    ' refer to our wiki: https://docs.metasploit.com/docs/using-metasploit/intermediate/running-private-modules.html')

                  # Avoid trying to use the search result if it exactly matches
                  # the module we were trying to load. The module cannot be
                  # loaded and searching isn't going to change that.
                  mods_found = cmd_search('-I', '-u', *args)
                end

                unless mods_found
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
              when Msf::MODULE_EVASION
                dispatcher = Msf::Ui::Console::CommandDispatcher::Evasion
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

            # If any additional datastore values were provided, set these values
            unless additional_datastore_values.nil? || additional_datastore_values.empty?
              mod.datastore.update(additional_datastore_values)
              print_status("Additionally setting #{additional_datastore_values.map { |k,v| "#{k} => #{v}" }.join(", ")}")
              if additional_datastore_values['TARGET'] && (mod.exploit? || mod.evasion?)
                mod.import_target_defaults
              end
            end

            # Choose a default payload when the module is used, not run
            if mod.datastore['PAYLOAD']
              print_status("Using configured payload #{mod.datastore['PAYLOAD']}")
            elsif dispatcher.respond_to?(:choose_payload)
              chosen_payload = dispatcher.choose_payload(mod)
              print_status("No payload configured, defaulting to #{chosen_payload}") if chosen_payload
            end

            if framework.features.enabled?(Msf::FeatureManager::DISPLAY_MODULE_ACTION) && mod.respond_to?(:actions) && mod.actions.size > 1
              print_status "Using action %grn#{mod.action.name}%clr - view all #{mod.actions.size} actions with the %grnshow actions%clr command"
            end

            mod.init_ui(driver.input, driver.output)
          end

          #
          # Command to take to the previously active module
          #
          def cmd_previous(*args)
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
            print_line "Previous module: #{@previous_module ? @previous_module.fullname : 'none'}"
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
                @module_name_stack.pop(args[0].to_i)
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

          def cmd_listm_help
            print_line 'Usage: listm'
            print_line
            print_line 'List the module stack'
            print_line
          end

          def cmd_listm(*_args)
            if @module_name_stack.empty?
              print_error('The module stack is empty')
              return
            end

            print_status("Module stack:\n")

            @module_name_stack.to_enum.with_index.reverse_each do |name, idx|
              print_line("[#{idx}]\t#{name}")
            end
          end

          def cmd_clearm_help
            print_line 'Usage: clearm'
            print_line
            print_line 'Clear the module stack'
            print_line
          end

          def cmd_clearm(*_args)
            print_status('Clearing the module stack')
            @module_name_stack.clear
          end

          #
          # Tab completion for the use command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

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

            log_msg = "Please see #{File.join(Msf::Config.log_directory, 'framework.log')} for details."

            # Check for modules that failed to load
            if framework.modules.module_load_error_by_path.length > 0
              wlog("WARNING! The following modules could not be loaded!")

              framework.modules.module_load_error_by_path.each do |path, _error|
                wlog("\t#{path}")
              end

              wlog(log_msg)
            end

            if framework.modules.module_load_warnings.length > 0
              wlog("The following modules were loaded with warnings:")

              framework.modules.module_load_warnings.each do |path, _error|
                wlog("\t#{path}")
              end

              wlog(log_msg)
            end

            self.driver.run_single('reload')
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
            end
          end

          def cmd_favorite_help
            print_line 'Usage: favorite [mod1 mod2 ...]'
            print_line
            print_line "Add one or multiple modules to the list of favorite modules stored in #{Msf::Config.fav_modules_file}"
            print_line 'If no module name is specified, the command will add the active module if there is one'
            print @@favorite_opts.usage
          end

          #
          # Helper method for cmd_favorite that writes modules to the fav_modules_file
          #
          def favorite_add(modules, favs_file)
            fav_limit = 50
            # obtain useful info about the fav_modules file
            exists, writable, readable, contents = favorite_check_fav_modules(favs_file)

            # if the fav_modules file exists, check the file permissions
            if exists
              case
              when !writable
                print_error("Unable to save module(s) to the favorite modules file because it is not writable")
                return
              when !readable
                print_error("Unable to save module(s) to the favorite modules file because it is not readable")
                return
              end
            end

            fav_count = 0
            if contents
              fav_count = contents.split.size
            end

            modules = modules.uniq # prevent modules from being added more than once
            modules.each do |name|
              mod = framework.modules.create(name)
              if (mod == nil)
                print_error("Invalid module: #{name}")
                next
              end

              if contents && contents.include?(mod.fullname)
                print_warning("Module #{mod.fullname} has already been favorited and will not be added to the favorite modules file")
                next
              end

              if fav_count >= fav_limit
                print_error("Favorite module limit (#{fav_limit}) exceeded. No more modules will be added.")
                return
              end

              File.open(favs_file, 'a+') { |file| file.puts(mod.fullname) }
              print_good("Added #{mod.fullname} to the favorite modules file")
              fav_count += 1
            end
            return
          end

          #
          # Helper method for cmd_favorite that deletes modules from the fav_modules_file
          #
          def favorite_del(modules, delete_all, favs_file)
            # obtain useful info about the fav_modules file
            exists, writable, readable, contents = favorite_check_fav_modules(favs_file)

            if delete_all
              custom_message = 'clear the contents of'
            else
              custom_message = 'delete module(s) from'
            end

            case # error handling based on the existence / permissions of the fav_modules file
            when !exists
              print_warning("Unable to #{custom_message} the favorite modules file because it does not exist")
              return
            when !writable
              print_error("Unable to #{custom_message} the favorite modules file because it is not writable")
              return
            when !readable
              unless delete_all
                print_error("Unable to #{custom_message} the favorite modules file because it is not readable")
                return
              end
            when contents.empty?
              print_warning("Unable to #{custom_message} the favorite modules file because it is already empty")
              return
            end

            if delete_all
              File.write(favs_file, '')
              print_good("Favorite modules file cleared")
              return
            end

            modules = modules.uniq # prevent modules from being deleted more than once
            contents = contents.split
            modules.each do |name|
              mod = framework.modules.create(name)
              if (mod == nil)
                print_error("Invalid module: #{name}")
                next
              end

              unless contents.include?(mod.fullname)
                print_warning("Module #{mod.fullname} cannot be deleted because it is not in the favorite modules file")
                next
              end

              contents.delete(mod.fullname)
              print_status("Removing #{mod.fullname} from the favorite modules file")
            end

            # clear the contents of the fav_modules file if removing the module(s) makes it empty
            if contents.length == 0
              File.write(favs_file, '')
              return
            end

            File.open(favs_file, 'w') { |file| file.puts(contents.join("\n")) }
          end

          #
          # Helper method for cmd_favorite that checks if the fav_modules file exists and is readable / writable
          #
          def favorite_check_fav_modules(favs_file)
            exists = false
            writable = false
            readable = false
            contents = ''

            if File.exist?(favs_file)
              exists = true
            end

            if File.writable?(favs_file)
              writable = true
            end

            if File.readable?(favs_file)
              readable = true
              contents = File.read(favs_file)
            end

            return exists, writable, readable, contents
          end

          #
          # Add modules to or delete modules from the fav_modules file
          #
          def cmd_favorite(*args)
            valid_custom_args = ['-c', '-d', '-l']
            favs_file = Msf::Config.fav_modules_file

            # always display the help banner if -h is provided or if multiple options are provided
            if args.include?('-h') || args.select{ |arg| arg if valid_custom_args.include?(arg) }.length > 1
              cmd_favorite_help
              return
            end

            # if no arguments were provided, check if there is an active module to add
            if args.empty?
              unless active_module
                print_error('No module has been provided to favorite.')
                cmd_favorite_help
                return
              end

              args = [active_module.fullname]
              favorite_add(args, favs_file)
              return
            end

            case args[0]
            when '-c'
              args.delete('-c')
              unless args.empty?
                print_error('Option `-c` does not support arguments.')
                cmd_favorite_help
                return
              end

              favorite_del(args, true, favs_file)
            when '-d'
              args.delete('-d')
              if args.empty?
                unless active_module
                  print_error('No module has been provided to delete.')
                  cmd_favorite_help
                  return
                end

                args = [active_module.fullname]
              end

              favorite_del(args, false, favs_file)
            when '-l'
              args.delete('-l')
              unless args.empty?
                print_error('Option `-l` does not support arguments.')
                cmd_favorite_help
                return
              end
              cmd_show('favorites')
            else # no valid options, but there are arguments
              if args[0].start_with?('-')
                print_error('Invalid option provided')
                cmd_favorite_help
                return
              end

              favorite_add(args, favs_file)
            end
          end

          def cmd_favorites_help
            print_line 'Usage: favorites'
            print_line
            print_line 'Print the list of favorite modules (alias for `show favorites`)'
            print_line 'You can use the %grnfavorite%clr command to add the current module to your favorites list'
            print @@favorites_opts.usage
          end

          #
          # Print the list of favorite modules from the fav_modules file (alias for `show favorites`)
          #
          def cmd_favorites(*args)
            if args.empty?
              cmd_show('favorites')
              return
            end

            # always display the help banner if the command is called with arguments
            unless args.include?('-h')
              print_error('Invalid option(s) provided')
            end

            cmd_favorites_help
          end

          #
          # Tab complete module names
          #
          def tab_complete_module(str, words)
            res = []
            module_metadata = Msf::Modules::Metadata::Cache.instance.get_metadata
            module_metadata.each do |m|
              res << "#{m.type}/#{m.ref_name}"
            end
            framework.modules.module_types.each do |mtyp|
              mset = framework.modules.module_names(mtyp)
              mset.each do |mref|
                res << mtyp + '/' + mref
              end
            end

            return dangerzone_modules_to_codenames(res.sort) if dangerzone_active?
            return res.uniq.sort
          end

          def print_april_fools_module_use
            return unless ENV['APRILFOOLSMODULEUSE'] || Time.now.strftime("%m%d") == "0401"

            banner = Msf::Ui::Banner.readfile('help-using-a-module.txt')
            print_line("%grn#{banner}%clr")
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

          def show_encoders # :nodoc:
            # If an active module has been selected and it's an exploit, get the
            # list of compatible encoders and display them
            if (active_module and active_module.exploit? == true)
              show_module_metadata('Compatible Encoders', active_module.compatible_encoders)
            else
              show_module_metadata('Encoders', 'encoder')
            end
          end

          def show_nops # :nodoc:
            show_module_metadata('NOP Generators', 'nop')
          end

          def show_exploits # :nodoc:
            show_module_metadata('Exploits', 'exploit')
          end

          def show_payloads # :nodoc:
            # If an active module has been selected and it's an exploit, get the
            # list of compatible payloads and display them
            if active_module && (active_module.exploit? || active_module.evasion?)
              @@payload_show_results = active_module.compatible_payloads

              show_module_metadata('Compatible Payloads', @@payload_show_results)
            else
              # show_module_set(‘Payloads’, framework.payloads, regex, minrank, opts)
              show_module_metadata('Payloads', 'payload')
            end
          end

          def show_auxiliary # :nodoc:
            show_module_metadata('Auxiliary','auxiliary')
          end

          def show_post # :nodoc:
            show_module_metadata('Post','post')
          end

          def show_evasion # :nodoc:
            show_module_metadata('Evasion','evasion')
          end

          def show_favorites # :nodoc:
            favs_file = Msf::Config.fav_modules_file

            unless File.exist?(favs_file)
              print_error("The favorite modules file does not exist")
              return
            end

            if File.zero?(favs_file)
              print_warning("The favorite modules file is empty")
              return
            end

            unless File.readable?(favs_file)
              print_error("Unable to read from #{favs_file}")
              return
            end

            # create module set using the saved modules
            fav_modules = {}

            # get the full module names from the favorites file and use then to search the MetaData Cache for matching modules
            saved_favs = File.readlines(favs_file).map(&:strip)
            saved_favs.each do |mod|
              # populate hash with module fullname and module object
              fav_modules[mod] = framework.modules[mod]
            end

            fav_modules.each do |fullname, mod_obj|
              if mod_obj.nil?
                print_warning("#{favs_file} contains a module that can not be found - #{fullname}.")
              end
            end

            # find cache module instance and add it to @module_search_results
            @module_search_results = Msf::Modules::Metadata::Cache.instance.find('fullname' => [saved_favs, []])

            # This scenario is for when a module fullname is a substring of other module fullnames
            # Example, searching for the payload/windows/meterpreter/reverse_tcp module can result in matches for:
            #   - windows/meterpreter/reverse_tcp_allports
            #   - windows/meterpreter/reverse_tcp_dns
            # So if @module_search_results is greater than the amount of fav_modules, we need to filter the results to be more accurate
            if fav_modules.length < @module_search_results.length
              filtered_results = []
              fav_modules.each do |fullname, _mod_obj|
                filtered_results << @module_search_results.select do |search_result|
                  search_result.fullname == fullname
                end
              end
              @module_search_results = filtered_results.flatten.sort_by(&:fullname)
            end
            @module_search_results_with_usage_metadata = @module_search_results.map { |mod| { mod: mod, datastore: {} } }

            show_module_metadata('Favorites', fav_modules)
            print_module_search_results_usage
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
              [ 'SessionTlvLogging', framework.datastore['SessionTlvLogging'] || "false", 'Log all incoming and outgoing TLV packets' ],
              [ 'TimestampOutput', framework.datastore['TimestampOutput'] || "false", 'Prefix all console output with a timestamp' ],
              [ 'Prompt', framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt.to_s.gsub(/%.../,"") , "The prompt string" ],
              [ 'PromptChar', framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar.to_s.gsub(/%.../,""), "The prompt character" ],
              [ 'PromptTimeFormat', framework.datastore['PromptTimeFormat'] || Time::DATE_FORMATS[:db].to_s, 'Format for timestamp escapes in prompts' ],
              [ 'MeterpreterPrompt', framework.datastore['MeterpreterPrompt'] || '%undmeterpreter%clr', 'The meterpreter prompt string' ],
            ].each { |r| tbl << r }

            print(tbl.to_s)
          end

          def show_targets(mod) # :nodoc:
            case mod
            when Msf::Exploit
              mod_targs = Serializer::ReadableText.dump_exploit_targets(mod, '', "\nExploit targets:")
              print("#{mod_targs}\n") if (mod_targs and mod_targs.length > 0)
            when Msf::Evasion
              mod_targs = Serializer::ReadableText.dump_evasion_targets(mod, '', "\nEvasion targets:")
              print("#{mod_targs}\n") if (mod_targs and mod_targs.length > 0)
            end
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
            print("\nView the full module info with the #{Msf::Ui::Tip.highlight('info')}, or #{Msf::Ui::Tip.highlight('info -d')} command.\n\n")
          end

          def show_evasion_options(mod) # :nodoc:
            mod_opt = Serializer::ReadableText.dump_evasion_options(mod, '   ')
            print("\nModule evasion options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

            # If it's an exploit and a payload is defined, create it and
            # display the payload's options
            if (mod.evasion? and mod.datastore['PAYLOAD'])
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
              'Header'  => 'Loaded Plugins',
              'Prefix'  => "\n",
              'Postfix' => "\n",
              'Columns' => [ 'Name', 'Description' ]
            )

            framework.plugins.each { |plugin|
              tbl << [ plugin.name, plugin.desc ]
            }

            # create an instance of core to call the list_plugins
            core = Msf::Ui::Console::CommandDispatcher::Core.new(driver)
            core.list_plugins
            print(tbl.to_s)
          end

          # @param [table_name] used to name table
          # @param [module_filter] this will either be a modules fullname, or it will be an Array(show payloads/encoders)
          # or a Hash(show favorites) containing fullname
          # @param [compatible_mod] handles logic for if there is an active module when the
          # `show` command is run
          #
          # Handles the filtering of modules that will be generated into a table
          def show_module_metadata(table_name, module_filter)
            count = -1
            tbl = generate_module_table(table_name)

            if module_filter.is_a?(Array) || module_filter.is_a?(Hash)
              module_filter.sort.each do |_mod_fullname, mod_obj|
                mod = nil

                begin
                  mod = mod_obj.new
                rescue ::Exception
                end
                next unless mod

                count += 1
                tbl << add_record(mod, count, true)
              end
            else
              results = Msf::Modules::Metadata::Cache.instance.find(
                'type' => [[module_filter], []]
              )
              # Loop over each module and gather data
              results.each do |mod, _value|
                count += 1
                tbl << add_record(mod, count, false)
              end
            end
            print(tbl.to_s)
          end

          # @param [mod] current module being passed in
          # @param [count] passes the count for each record
          # @param [compatible_mod] handles logic for if there is an active module when the
          # `show` command is run
          #
          # Adds a record for a table, also handle logic for whether the module is currently
          # handling compatible payloads/encoders
          def add_record(mod, count, compatible_mod)
            if compatible_mod
              check = mod.has_check? ? 'Yes' : 'No'
            else
              check = mod.check ? 'Yes' : 'No'
            end
            [
              count,
              mod.fullname,
              mod.disclosure_date.nil? ? '' : mod.disclosure_date.strftime('%Y-%m-%d'),
              mod.rank,
              check,
              mod.name
            ]
          end

          def generate_module_table(type, search_terms = [], row_filter = nil) # :nodoc:
            table_hierarchy_formatters = framework.features.enabled?(Msf::FeatureManager::HIERARCHICAL_SEARCH_TABLE) ? [Msf::Ui::Console::TablePrint::BlankFormatter.new] : []

              Table.new(
                Table::Style::Default,
                'Header'     => type,
                'Prefix'     => "\n",
                'Postfix'    => "\n",
                'SearchTerm' => row_filter,
                'SortIndex' => -1,
                # For now, don't perform any word wrapping on the search table as it breaks the workflow of
                # copying module names in conjunction with the `use <paste-buffer>` command
                'WordWrap' => false,
                'Columns' => [
                  '#',
                  'Name',
                  'Disclosure Date',
                  'Rank',
                  'Check',
                  'Description'
                ],
                'ColProps' => {
                  'Rank' => {
                    'Formatters' => [
                      *table_hierarchy_formatters,
                      Msf::Ui::Console::TablePrint::RankFormatter.new
                    ],
                    'Stylers' => [
                      Msf::Ui::Console::TablePrint::RankStyler.new
                    ]
                  },
                  'Name' => {
                    'Strip' => false,
                    'Stylers' => [Msf::Ui::Console::TablePrint::HighlightSubstringStyler.new(search_terms)]
                  },
                  'Check' => {
                    'Formatters' => [
                      *table_hierarchy_formatters,
                    ]
                  },
                  'Disclosure Date' => {
                    'Formatters' => [
                      *table_hierarchy_formatters,
                    ]
                  },
                  'Description' => {
                    'Stylers' => [
                      Msf::Ui::Console::TablePrint::HighlightSubstringStyler.new(search_terms)
                    ]
                  }
                }
              )
          end
        end
      end
    end
  end
end
