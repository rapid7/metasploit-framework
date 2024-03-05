# -*- coding: binary -*-

require 'pathname'

module Rex
  module Post
    module SMB
      module Ui
        ###
        #
        # SMB client commands for running modules
        #
        ###
        class Console::CommandDispatcher::Modules

          include Rex::Post::SMB::Ui::Console::CommandDispatcher


          #
          # List of supported commands.
          #
          def commands
            cmds = {
              'run' => 'Run a module'
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          #
          # Modules
          #
          def name
            'Modules'
          end

          def cmd_run_help
            print_line 'Usage: Modules'
            print_line
            print_line 'Run a module.'
            print_line
          end

          #
          # Executes a module/script in the context of the smb session.
          #
          def cmd_run(*args)
            if args.empty? || args.first == '-h' || args.first == '--help'
              cmd_run_help
              return true
            end

            # Get the script name
            begin
              script_name = args.shift
              # First try it as a module if we have access to the Metasploit
              # Framework instance.  If we don't, or if no such module exists,
              # fall back to using the scripting interface.
              if msf_loaded? && (mod = session.framework.modules.create(script_name))
                original_mod = mod
                reloaded_mod = session.framework.modules.reload_module(original_mod)

                unless reloaded_mod
                  error = session.framework.modules.module_load_error_by_path[original_mod.file_path]
                  print_error("Failed to reload module: #{error}")

                  return
                end

                opts = ''

                opts << (args + [ "SESSION=#{session.sid}" ]).join(',')
                result = reloaded_mod.run_simple(
                  'LocalInput' => shell.input,
                  'LocalOutput' => shell.output,
                  'OptionStr' => opts
                )

                print_status("Session #{result.sid} created in the background.") if result.is_a?(Msf::Session)
              else
                # the rest of the arguments get passed in through the binding
                session.execute_script(script_name, args)
              end
            rescue StandardError => e
              print_error("Error in script: #{script_name}")
              elog("Error in script: #{script_name}", error: e)
            end
          end
        end
      end
    end
  end
end
