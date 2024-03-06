# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      ###
      #
      # This module provides commands for the local file system
      #
      ###
      module LocalFileSystem
        #
        # Options for the lls command
        #
        @@lls_opts = Rex::Parser::Arguments.new(
          '-h' => [ false, 'Help banner' ],
          '-S' => [ true, 'Search string on filename (as regular expression)' ],
          '-t' => [ false, 'Sort by time' ],
          '-s' => [ false, 'Sort by size' ],
          '-r' => [ false, 'Reverse sort order' ]
        )

        #
        # List of supported local commands.
        #
        # @return [Hash] Hash of local commands
        def local_fs_commands
          {
            'getlwd' => 'Print local working directory (alias for lpwd)',
            'lcat' => 'Read the contents of a local file to the screen',
            'lcd' => 'Change local working directory',
            'lmkdir' => 'Create new directory on local machine',
            'lpwd' => 'Print local working directory',
            'lls' => 'List local files',
            'ldir' => 'List local files (alias for lls)'
          }
        end

        #
        # List local files
        #
        # @param [Array] args
        # @return [Rex::Text::Table] The results lls command
        def cmd_lls(*args)
          # Set Defaults
          path = ::Dir.pwd
          sort = 'Name'
          order = :forward
          search_term = nil

          # Parse the args
          @@lls_opts.parse(args) do |opt, _idx, val|
            case opt
              # Sort options
            when '-s'
              sort = 'Size'
            when '-t'
              sort = 'Last modified'
              # Output options
            when '-r'
              order = :reverse
              # Search
            when '-S'
              search_term = val
              if search_term.nil?
                print_error('Enter a search term')
                return true
              else
                search_term = /#{search_term}/nmi
              end
              # Help and path
            when '-h'
              cmd_lls_help
              return 0
            when nil
              path = val
            end
          end

          list_local_path(path, sort, order, search_term)
        end

        #
        # Help output for lss command
        #
        # @return [Rex::Parser::Arguments]
        def cmd_lls_help
          print_line 'Usage: lls [options]'
          print_line
          print_line 'Lists contents of a local directory or file info'
          print_line @@lls_opts.usage
        end

        #
        # Alias the lls command to dir, for those of us who have windows muscle-memory
        #
        alias cmd_ldir cmd_lls

        #
        # Change the local working directory.
        #
        # @param [Array] args
        # @return [TrueClass]
        def cmd_lcd(*args)
          if args.empty?
            print_line('Usage: lcd directory')
            return true
          end

          ::Dir.chdir(args[0])

          true
        end

        #
        # Tab completion for the lcd command
        #
        # @param [String] str
        # @param [Array] words
        def cmd_lcd_tabs(str, words)
          tab_complete_directory(str, words)
        end

        alias cmd_lls_tabs cmd_lcd_tabs

        #
        # Get list local path information for lls command
        #
        # @param [String] path
        # @param [String] sort
        # @param [Symbol] order
        # @param [nil] search_term
        # @return [Rex::Text::Table, String] The results lcd command
        def list_local_path(path, sort, order, search_term = nil)
          # Single file as path
          unless ::File.directory?(path)
            perms = pretty_perms(path)
            stat = ::File.stat(path)
            print_line("#{perms}  #{stat.size}  #{stat.ftype[0, 3]}  #{stat.mtime}  #{path}")
            return
          end

          # Enumerate each item...
          # No need to sort as Table will do it for us
          columns = [ 'Mode', 'Size', 'Type', 'Last modified', 'Name' ]
          tbl = Rex::Text::Table.new(
            'Header' => "Listing Local: #{path}",
            'SortIndex' => columns.index(sort),
            'SortOrder' => order,
            'Columns' => columns
          )

          items = 0
          files = ::Dir.entries(path)

          files.each do |file|
            file_path = ::File.join(path, file)

            perms = pretty_perms(file_path)
            stat = ::File.stat(file_path)

            row = [
              perms || '',
              stat.size ? stat.size.to_s : '',
              stat.ftype ? stat.ftype[0, 3] : '',
              stat.mtime || '',
              file
            ]
            if file != '.' && file != '..' && (row.join(' ') =~ /#{search_term}/)
              tbl << row
              items += 1
            end
          end
          if items > 0
            print_line(tbl.to_s)
          else
            print_line("No entries exist in #{path}")
          end
        end

        #
        # Reads the contents of a local file and prints them to the screen.
        #
        # @param [Array] args
        # @return [TrueClass]
        def cmd_lcat(*args)
          if args.empty? || args.include?('-h') || args.include?('--help')
            print_line('Usage: lcat file')
            return true
          end

          path = args[0]
          path = ::File.expand_path(path) if path =~ path_expand_regex

          if ::File.stat(path).directory?
            print_error("#{path} is a directory")
          else
            fd = ::File.new(path, 'rb')
            begin
              print(fd.read) until fd.eof?
              # EOFError is raised if file is empty, do nothing, just catch
            rescue EOFError
            end
            fd.close
          end

          true
        end

        #
        # Tab completion for the lcat command
        #
        # @param [Object] str
        # @param [Object] words
        # @return [Array] List of matches
        def cmd_lcat_tabs(str, words)
          tab_complete_filenames(str, words)
        end

        #
        # Create new directory on local machine
        #
        # @param [Array] args
        # @return [Array]
        def cmd_lmkdir(*args)
          if args.empty?
            print_line('Usage: lmkdir </path/to/directory>')
            return
          end

          args.each do |path|
            ::FileUtils.mkdir_p(path)
            print_line("Directory '#{path}' created successfully.")
          rescue ::StandardError => e
            print_error("Error creating #{path} directory: #{e}")
          end
        end

        #
        # Display the local working directory.
        #
        # @param [Array] args
        # @return [TrueClass]
        def cmd_lpwd(*args)
          print_line(::Dir.pwd)
          true
        end

        alias cmd_getlwd cmd_lpwd

        #
        # Code from prettymode in lib/rex/post/file_stat.rb
        # adapted for local file usage
        #
        # @param [Object] path
        # @return [String]
        def pretty_perms(path)
          m = ::File.stat(path).mode
          om = '%04o' % m
          perms = ''

          3.times do
            perms = ((m & 0o1) == 0o1 ? 'x' : '-') + perms
            perms = ((m & 0o2) == 0o2 ? 'w' : '-') + perms
            perms = ((m & 0o4) == 0o4 ? 'r' : '-') + perms
            m >>= 3
          end

          "#{om}/#{perms}"
        end

        private

        # @return [Regexp]
        def path_expand_regex
          if shell.session.platform == 'windows'
            /%(\w*)%/
          else
            /\$(([A-Za-z0-9_]+)|\{([A-Za-z0-9_]+)\})|^~/
          end
        end
      end
    end
  end
end
