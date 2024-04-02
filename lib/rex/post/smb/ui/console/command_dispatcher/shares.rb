# -*- coding: binary -*-

require 'pathname'
require 'rex/post/file'
require 'filesize'

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
          # Initializes an instance of the shares command set using the supplied console
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

          @@upload_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@download_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@delete_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@mkdir_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          @@rmdir_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu' ]
          )

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              'shares' => 'View the available shares and interact with one',
              'ls' => 'List all files in the current directory',
              'dir' => 'List all files in the current directory (alias for ls)',
              'pwd' => 'Print the current remote working directory',
              'cd' => 'Change the current remote working directory',
              'cat' => 'Read the file at the given path',
              'upload' => 'Upload a file',
              'download' => 'Download a file',
              'delete' => 'Delete a file',
              'mkdir' => 'Make a new directory',
              'rmdir' => 'Delete a directory'
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
              populate_shares

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
              populate_shares if @valid_share_names.nil?
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

            remote_path = ''

            @@delete_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                remote_path = val
              else
                print_warning('Too many parameters')
                cmd_ls_help
                return
              end
            end

            full_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(remote_path).to_s)

            files = active_share.list(directory: full_path)
            table = Rex::Text::Table.new(
              'Header' => "ls #{full_path}",
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

          def cmd_ls_help
            print_line 'Usage:'
            print_line 'ls [options] [path]'
            print_line
            print_line 'COMMAND ALIASES:'
            print_line
            print_line '    dir'
            print_line
            print_line 'Lists contents of directory or file info'
            print_line @@ls_opts.usage
          end

          def cmd_ls_tabs(_str, words)
            return [] if words.length > 1

            @@ls_opts.option_keys
          end

          #
          # Alias the ls command to dir, for those of us who have windows muscle-memory
          #
          alias cmd_dir cmd_ls
          alias cmd_dir_help cmd_ls_help
          alias cmd_dir_tabs cmd_ls_tabs

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

            share_name = active_share.share[/[^\\].*$/, 0]
            cwd = shell.cwd.blank? ? '' : "\\#{shell.cwd}"
            print_line "Current directory is \\\\#{share_name}#{cwd}\\"
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
            native_path = Pathname.new(shell.cwd).join(path).to_s
            new_path = Rex::Ntpath.as_ntpath(native_path)
            begin
              response = active_share.open_directory(directory: new_path)
              directory = RubySMB::SMB2::File.new(name: new_path, tree: active_share, response: response, encrypt: @tree_connect_encrypt_data)
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
            ensure
              directory.close if directory
            end

            shell.cwd = native_path
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

            return print_no_share_selected unless active_share

            path = args[0]

            new_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(path).to_s)

            begin
              file = simple_client.open(new_path, 'o')
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

            @@cd_opts.option_keys
          end

          def cmd_upload(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_upload_help
              return
            end

            return print_no_share_selected unless active_share

            local_path = nil
            remote_path = nil

            @@upload_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                local_path = val
              when 1
                remote_path = val
              else
                print_warning('Too many parameters')
                cmd_upload_help
                return
              end
            end

            if local_path.blank?
              print_error('No local path given')
              return
            end

            remote_path = Rex::Post::File.basename(local_path) if remote_path.nil?
            full_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(remote_path).to_s)

            upload_file(full_path, local_path)

            print_good("#{local_path} uploaded to #{full_path}")
          end

          def cmd_upload_tabs(str, words)
            tab_complete_filenames(str, words)
          end

          def cmd_upload_help
            print_line 'Usage: upload <local_path> <remote_path>'
            print_line
            print_line 'Upload a file to the remote target.'
            print @@upload_opts.usage
          end

          def cmd_download(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_download_help
              return
            end

            return print_no_share_selected unless active_share

            remote_path = nil
            local_path = nil

            @@download_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                remote_path = val
              when 1
                local_path = val
              else
                print_warning('Too many parameters')
                cmd_download_help
                return
              end
            end

            if remote_path.blank?
              print_error('No remote path given')
              return
            end

            local_path = Rex::Post::File.basename(remote_path) if local_path.nil?
            full_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(remote_path).to_s)

            download_file(local_path, full_path)

            print_good("Downloaded #{full_path} to #{local_path}")
          end

          def cmd_download_help
            print_line 'Usage: download <remote_path> <local_path>'
            print_line
            print_line 'Download a file from the remote target.'
            print @@download_opts.usage
          end

          def cmd_delete(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_delete_help
              return
            end
            remote_path = nil

            @@delete_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                remote_path = val
              else
                print_warning('Too many parameters')
                cmd_delete_help
                return
              end
            end

            full_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(remote_path).to_s)
            fd = simple_client.open(full_path, 'o')
            fd.delete
            print_good("Deleted #{full_path}")
          end

          def cmd_delete_help
            print_line 'Usage: delete <remote_path>'
            print_line
            print_line 'Delete a file from the remote target.'
            print @@delete_opts.usage
          end

          def cmd_mkdir(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_mkdir_help
              return
            end

            return print_no_share_selected unless active_share

            remote_path = nil

            @@mkdir_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                remote_path = val
              else
                print_warning('Too many parameters')
                cmd_mkdir_help
                return
              end
            end

            full_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(remote_path).to_s)

            response = active_share.open_directory(directory: full_path, disposition: RubySMB::Dispositions::FILE_CREATE)
            directory = RubySMB::SMB2::File.new(name: full_path, tree: active_share, response: response, encrypt: @tree_connect_encrypt_data)
            print_good("Directory #{full_path} created")
          ensure
            directory.close if directory
          end

          def cmd_mkdir_help
            print_line 'Usage: mkdir <remote_path>'
            print_line
            print_line 'Create a directory on the remote target.'
            print @@mkdir_opts.usage
          end

          def cmd_rmdir(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_rmdir_help
              return
            end

            return print_no_share_selected unless active_share

            remote_path = nil

            @@rmdir_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                remote_path = val
              else
                print_warning('Too many parameters')
                cmd_rmdir_help
                return
              end
            end

            full_path = Rex::Ntpath.as_ntpath(Pathname.new(shell.cwd).join(remote_path).to_s)

            response = active_share.open_directory(directory: full_path, write: true, delete: true, desired_delete: true)
            directory = RubySMB::SMB2::File.new(name: full_path, tree: active_share, response: response, encrypt: @tree_connect_encrypt_data)
            status = directory.delete
            if status == WindowsError::NTStatus::STATUS_SUCCESS
              print_good("Deleted #{full_path}")
            else
              print_error("Error deleting #{full_path}: #{status.name}, #{status.description}")
            end
          ensure
            directory.close if directory
          end

          def cmd_rmdir_help
            print_line 'Usage: rmdir <remote_path>'
            print_line
            print_line 'Delete a directory from the remote target.'
            print @@rmdir_opts.usage
          end

          protected

          def print_no_share_selected
            print_error('No active share selected. Use the %grnshares%clr command to view available shares, and %grnshares -i <id>%clr to interact with one')
            nil
          end

          # Upload a local file to the target
          # @param dest_file [String] The path for the destination file
          # @param src_file [String] The path for the source file
          def upload_file(dest_file, src_file)
            buf_size = 8 * 1024 * 1024
            begin
              dest_fd = simple_client.open(dest_file, 'wct', write: true)
              src_fd = ::File.open(src_file, "rb")
              src_size = src_fd.stat.size
              offset = 0
              while (buf = src_fd.read(buf_size))
                offset = dest_fd.write(buf, offset)
                percent = offset / src_size.to_f * 100.0
                msg = "Uploaded #{Filesize.new(offset).pretty} of " \
                "#{Filesize.new(src_size).pretty} (#{percent.round(2)}%)"
                print_status(msg)
              end
            ensure
              src_fd.close unless src_fd.nil?
              dest_fd.close unless dest_fd.nil?
            end
          end

          # Download a remote file from the target
          # @param dest_file [String] The path for the destination file
          # @param src_file [String] The path for the source file
          def download_file(dest_file, src_file)
            buf_size = 8 * 1024 * 1024
            src_fd = simple_client.open(src_file, 'o')
            # Make the destination path if necessary
            dir = ::File.dirname(dest_file)
            ::FileUtils.mkdir_p(dir) if dir && !::File.directory?(dir)
            dst_fd = ::File.new(dest_file, "wb")

            offset = 0
            src_size = client.open_files[src_fd.file_id].size
            begin
              while offset < src_size
                data = src_fd.read(buf_size, offset)
                dst_fd.write(data)
                offset += data.length
                percent = offset / src_size.to_f * 100.0
                msg = "Downloaded #{Filesize.new(offset).pretty} of " \
                  "#{Filesize.new(src_size).pretty} (#{percent.round(2)}%)"
                print_status(msg)
              end
            ensure
              src_fd.close unless src_fd.nil?
              dst_fd.close unless dst_fd.nil?
            end
          end

          private

          def populate_shares
            @share_search_results = client.net_share_enum_all(session.address)
            @valid_share_names = @share_search_results.map { |result| result[:name] }
          end
        end
      end
    end
  end
end
