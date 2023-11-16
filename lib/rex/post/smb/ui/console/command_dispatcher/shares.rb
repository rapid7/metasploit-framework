# -*- coding: binary -*-

require 'pathname'

module Rex
  module Post
    module SMB
      module Ui
        ###
        #
        # Core SMB client commands
        #
        ###
        class Console::CommandDispatcher::Shares

          include Rex::Post::SMB::Ui::Console::CommandDispatcher

          #
          # Initializes an instance of the core command set using the supplied console
          # for interactivity.
          #
          # @param [Rex::Post::SMB::Ui::Console] console
          def initialize(console)
            super

            @share_search_results = []
          end

          @@shares_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ],
            ['-l', '--list'] => [ false, 'List all shares'],
            ['-i', '--interact'] => [ true, 'Interact with the supplied share ID', '<id>']
          )

          @@ls_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@pwd_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@cd_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@cat_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              'shares' => 'View the available shares and interact with one',
              'ls' => 'List all files in the current directory',
              'pwd' => 'Print the current remote working directory',
              'cd' => 'Change the current remote working directory',
              'cat' => 'Read the file at the given path'
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          #
          # Shares
          #
          def name
            'Shares'
          end

          #
          # View and interact with shares
          #
          def cmd_shares(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_shares_help
              return
            end

            method = :list
            share_name = nil

            # Parse options
            @@shares_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-l', '--list'
              when '-i', '--interact'
                share_name = val
                method = :interact
              end
            end

            # Perform action
            case method
            when :list
              @share_search_results = client.net_share_enum_all(session.address)
              @valid_share_names = @share_search_results.map { |result| result[:name] }

              table = Rex::Text::Table.new(
                'Header' => 'Shares',
                'Indent' => 4,
                'Columns' => %w[# Name Type comment],
                'Rows' => @share_search_results.map.with_index do |share, i|
                  [i, share[:name], share[:type], share[:comment]]
                end
              )

              print_line table.to_s
            when :interact
              # Share names can be comprised only of digits so prioritise a share name over the share index
              if share_name.match?(/\A\d+\z/) && !@valid_share_names.include?(share_name)
                share_name = (@share_search_results[share_name.to_i] || {})[:name]
              end

              if share_name.nil?
                print_error('Invalid share name')
                return
              end

              path = "\\\\#{session.address}\\#{share_name}"
              begin
                shell.active_share = client.tree_connect(path)
                shell.cwd = ''
                print_good "Successfully connected to #{share_name}"
              rescue StandardError => e
                log_error("Error running action #{method}: #{e.class} #{e}")
              end
            end
          end

          def cmd_shares_tabs(_str, words)
            return [] if words.length > 1

            @@shares_opts.option_keys
          end

          def cmd_shares_help
            print_line 'Usage: shares'
            print_line
            print_line 'View the shares available on the remote target.'
            print @@shares_opts.usage
          end

          #
          # Display the contents of your current working directory
          #
          def cmd_ls(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_ls_help
              return
            end

            return print_no_share_selected unless active_share

            files = active_share.list(directory: as_ntpath(shell.cwd))
            table = Rex::Text::Table.new(
              'Header' => 'Shares',
              'Indent' => 4,
              'Columns' => [ '#', 'Type', 'Name', 'Created', 'Accessed', 'Written', 'Changed', 'Size'],
              'Rows' => files.map.with_index do |file, i|
                name = file.file_name.encode('UTF-8')
                create_time = file.create_time.to_datetime
                last_access = file.last_access.to_datetime
                last_write = file.last_write.to_datetime
                last_change = file.last_change.to_datetime
                if (file[:file_attributes]&.directory == 1) || (file[:ext_file_attributes]&.directory == 1)
                  type = 'DIR'
                else
                  type = 'FILE'
                  size = file.end_of_file
                end

                [i, type || 'Unknown', name, create_time, last_access, last_write, last_change, size]
              end
            )

            print_line table.to_s
          end

          def cmd_ls_tabs(_str, words)
            return [] if words.length > 1

            @@ls_opts.option_keys
          end

          def cmd_pwd_help
            print_line 'Usage: pwd'
            print_line
            print_line 'Print the current remote working directory.'
            print_line
          end

          #
          # Print the current working directory
          #
          def cmd_pwd(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_pwd_help
              return
            end

            return print_no_share_selected unless active_share

            print_line shell.cwd || ''
          end

          def cmd_pwd_tabs(_str, words)
            return [] if words.length > 1

            @@pwd_opts.option_keys
          end

          def cmd_cd_help
            print_line 'Usage: cd <path>'
            print_line
            print_line 'Change the current remote working directory.'
            print_line
          end

          #
          # Change directory
          #
          def cmd_cd(*args)
            if args.include?('-h') || args.include?('--help') || args.length != 1
              cmd_cd_help
              return
            end

            return print_no_share_selected unless active_share

            path = args[0]
            # TODO: Needs better normalization
            new_path = as_ntpath(Pathname.new(shell.cwd).join(path).to_s)
            begin
              response = active_share.open_directory(directory: new_path)
              directory = RubySMB::SMB2::File.new(name: new_path, tree: active_share, response: response, encrypt: @tree_connect_encrypt_data)
              directory.close
            rescue RubySMB::Error::UnexpectedStatusCode => e
              # Special case this error to provide better feedback to the user
              # since I think trying to `cd` to a non-existent directory is pretty likely to accidentally happen
              if e.status_code == WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
                print_error("The path `#{new_path}` is not a valid directory")
              end
              print_error(e.message)
              elog(e)
              return
            rescue StandardError => e
              print_error('Unknown error occurred while trying to change directory')
              elog(e)
              return
            end

            shell.cwd = new_path
          end

          def cmd_cat_help
            print_line 'Usage: cat <path>'
            print_line
            print_line 'Read the file at the given path.'
            print_line
          end

          #
          # Print the contents of a file
          #
          def cmd_cat(*args)
            if args.include?('-h') || args.include?('--help') || args.length != 1
              cmd_cd_help
              return
            end

            return print_no_share_selected if !active_share

            path = args[0]
            # TODO: Needs better normalization
            new_path = as_ntpath(Pathname.new(shell.cwd).join(path).to_s)

            begin
              file = active_share.open_file(filename: new_path)
              result = file.read
              print_line(result)
            rescue StandardError => e
              print_error("#{e.class} #{e}")
              return
            ensure
              begin
                file.close if file
              rescue StandardError => e
                elog(e)
              end
            end
          end

          def cmd_cd_tabs(_str, words)
            return [] if words.length > 1

            @@cat_opts.option_keys
          end

          protected

          def print_no_share_selected
            print_error('No active share selected')
            nil
          end

          def as_ntpath(path)
            Pathname.new(path)
                    .cleanpath
                    .each_filename
                    .drop_while { |file| file == '.' || file == '..' }
                    .join('\\')
          end
        end
      end
    end
  end
end
