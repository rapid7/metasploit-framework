# frozen_string_literal: true

module Msf
  module Ui
    module Console
      module CommandDispatcher
        module Session
          include Rex::Ui::Text::DispatcherShell::CommandDispatcher

          @@irb_opts = Rex::Parser::Arguments.new(
            %w[-h --help] => [false, 'Help menu.' ],
            '-e' => [true, 'Expression to evaluate.']
          )
          def commands
            {
              '?' => 'Help menu',
              'background' => 'Backgrounds the current session',
              'bg' => 'Alias for background',
              'exit' => 'Terminate the session',
              'help' => 'Help menu',
              'irb' => 'Open an interactive Ruby shell on the current session',
              'pry' => 'Open the Pry debugger on the current session',
              'quit' => 'Terminate the session',
              'resource' => 'Run the commands stored in a file',
              'uuid' => 'Get the UUID for the current session',
              'sessions' => 'Quickly switch to another session'
            }
          end

          def cmd_background_help
            print_line('Usage: background')
            print_line
            print_line('Stop interacting with this session and return to the parent prompt')
            print_line
          end

          def cmd_background(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_background_help
              return
            end
            print_status("Backgrounding session #{session.name}...")
            session.interacting = false
          end

          alias cmd_bg cmd_background
          alias cmd_bg_help cmd_background_help

          #
          # Terminates the session.
          #
          def cmd_exit(*args)
            print_status("Shutting down session: #{session.sid}")
            session.exit
          end

          alias cmd_quit cmd_exit

          def cmd_irb_help
            print_line('Usage: irb')
            print_line
            print_line('Open an interactive Ruby shell on the current session.')
            print @@irb_opts.usage
          end

          def cmd_irb_tabs(str, words)
            return [] if words.length > 1

            @@irb_opts.option_keys
          end

          #
          # Open an interactive Ruby shell on the current session
          #
          def cmd_irb(*args)
            expressions = []

            # Parse the command options
            @@irb_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-e'
                expressions << val
              when '-h', '--help'
                return cmd_irb_help
              end
            end

            framework = session.framework

            if expressions.empty?
              print_status('Starting IRB shell...')
              print_status("You are in the session object\n")
              framework.history_manager.with_context(name: :irb) do
                Rex::Ui::Text::IrbShell.new(session).run
              end
            else
              # XXX: No vprint_status here
              if framework.datastore['VERBOSE'].to_s == 'true'
                print_status("You are executing expressions in #{binding.receiver}")
              end

              expressions.each { |expression| eval(expression, binding) }
            end
          end

          def cmd_pry_help
            print_line 'Usage: pry'
            print_line
            print_line 'Open the Pry debugger on the current session.'
            print_line
          end

          #
          # Open the Pry debugger on the current session
          #
          def cmd_pry(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_pry_help
              return
            end

            begin
              require 'pry'
            rescue LoadError
              print_error('Failed to load Pry, try "gem install pry"')
              return
            end

            print_status('Starting Pry shell...')
            print_status("You are in the session object\n")

            Pry.config.history_load = false
            session.framework.history_manager.with_context(history_file: Msf::Config.pry_history, name: :pry) do
              session.pry
            end
          end

          def cmd_sessions_help
            print_line('Usage: sessions <id>')
            print_line
            print_line('Interact with a different session Id.')
            print_line('This works the same as calling this from the MSF shell: sessions -i <session id>')
            print_line
          end

          def cmd_sessions(*args)
            if args.empty? || args[0].to_i == 0
              cmd_sessions_help
            elsif args[0].to_s == session.name.to_s
              print_status("Session #{session.name} is already interactive.")
            else
              print_status("Backgrounding session #{session.name}...")
              # store the next session id so that it can be referenced as soon
              # as this session is no longer interacting
              session.next_session = args[0]
              session.interacting = false
            end
          end

          def cmd_resource_help
            print_line 'Usage: resource path1 [path2 ...]'
            print_line
            print_line 'Run the commands stored in the supplied files. (- for stdin, press CTRL+D to end input from stdin)'
            print_line 'Resource files may also contain ERB or Ruby code between <ruby></ruby> tags.'
            print_line
          end

          def cmd_resource(*args)
            if args.empty? || args.include?('-h') || args.include?('--help')
              cmd_resource_help
              return false
            end

            args.each do |res|
              good_res = nil
              if res == '-'
                good_res = res
              elsif ::File.exist?(res)
                good_res = res
              elsif [
                ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
                ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter'
              ].each do |dir|
                      res_path = dir + ::File::SEPARATOR + res
                      if ::File.exist?(res_path)
                        good_res = res_path
                        break
                      end
                    end
                # let's check to see if it's in the scripts/resource dir (like when tab completed)
              end
              unless good_res
                print_error("#{res} is not a valid resource file")
                next
              end

              session.console.load_resource(good_res)
            end
          end

          def cmd_resource_tabs(str, words)
            tabs = []
            # return tabs if words.length > 1
            if (str && str =~ (/^#{Regexp.escape(::File::SEPARATOR)}/))
              # then you are probably specifying a full path so let's just use normal file completion
              return tab_complete_filenames(str, words)
            elsif (!(words[1]) || !words[1].match(%r{^/}))
              # then let's start tab completion in the scripts/resource directories
              begin
                [
                  ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
                  ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
                  '.'
                ].each do |dir|
                  next if !::File.exist? dir

                  tabs += ::Dir.new(dir).find_all do |e|
                    path = dir + ::File::SEPARATOR + e
                    ::File.file?(path) and ::File.readable?(path)
                  end
                end
              rescue StandardError => e
                elog('Problem tab completing resource file names in the scripts/resource directories', error: e)
              end
            else
              tabs += tab_complete_filenames(str, words)
            end

            return tabs
          end
        end
      end
    end
  end
end
