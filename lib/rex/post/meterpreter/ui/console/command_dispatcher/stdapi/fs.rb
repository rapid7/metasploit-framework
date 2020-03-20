# -*- coding: binary -*-
require 'tempfile'
require 'filesize'
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The file system portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Fs

  Klass = Console::CommandDispatcher::Stdapi::Fs

  include Console::CommandDispatcher

  CHECKSUM_ALGORITHMS = %w{ md5 sha1 }
  private_constant :CHECKSUM_ALGORITHMS
  PATH_EXPAND_REGEX = /\%(\w*)\%/
  private_constant :PATH_EXPAND_REGEX

  #
  # Options for the download command.
  #
  @@download_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-c" => [ false, "Resume getting a partially-downloaded file" ],
    "-a" => [ false, "Enable adaptive download buffer size" ],
    "-b" => [ true,  "Set the initial block size for the download" ],
    "-l" => [ true,  "Set the limit of retries (0 unlimits)" ],
    "-r" => [ false, "Download recursively" ],
    "-t" => [ false, "Timestamp downloaded files" ])

  #
  # Options for the upload command.
  #
  @@upload_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-r" => [ false, "Upload recursively" ])
  
  #
  # Options for the ls command
  #
  @@ls_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-S" => [ true,  "Search string on filename (as regular expression)" ],
    "-t" => [ false, "Sort by time" ],
    "-s" => [ false, "Sort by size" ],
    "-r" => [ false, "Reverse sort order" ],
    "-x" => [ false, "Show short file names" ],
    "-l" => [ false, "List in long format (default)" ],
    "-R" => [ false, "Recursively list subdirectories encountered" ])

  #
  # Options for the lls command
  #
  @@lls_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-S" => [ true,  "Search string on filename (as regular expression)" ],
    "-t" => [ false, "Sort by time" ],
    "-s" => [ false, "Sort by size" ],
    "-r" => [ false, "Reverse sort order" ])

  #
  # List of supported commands.
  #
  def commands
    all = {
      'cat'        => 'Read the contents of a file to the screen',
      'cd'         => 'Change directory',
      'checksum'   => 'Retrieve the checksum of a file',
      'del'        => 'Delete the specified file',
      'dir'        => 'List files (alias for ls)',
      'download'   => 'Download a file or directory',
      'edit'       => 'Edit a file',
      'getlwd'     => 'Print local working directory',
      'getwd'      => 'Print working directory',
      'lcd'        => 'Change local working directory',
      'lpwd'       => 'Print local working directory',
      'ls'         => 'List files',
      'lls'        => 'List local files',
      'mkdir'      => 'Make directory',
      'pwd'        => 'Print working directory',
      'rm'         => 'Delete the specified file',
      'mv'         => 'Move source to destination',
      'cp'         => 'Copy source to destination',
      'chmod'      => 'Change the permissions of a file',
      'rmdir'      => 'Remove directory',
      'search'     => 'Search for files',
      'upload'     => 'Upload a file or directory',
      'show_mount' => 'List all mount points/logical drives',
    }

    reqs = {
      'cat'        => [],
      'cd'         => ['stdapi_fs_chdir'],
      'checksum'   => CHECKSUM_ALGORITHMS.map { |a| "stdapi_fs_#{a}" },
      'del'        => ['stdapi_fs_rm'],
      'dir'        => ['stdapi_fs_stat', 'stdapi_fs_ls'],
      'download'   => [],
      'edit'       => [],
      'getlwd'     => [],
      'getwd'      => ['stdapi_fs_getwd'],
      'lcd'        => [],
      'lpwd'       => [],
      'ls'         => ['stdapi_fs_stat', 'stdapi_fs_ls'],
      'lls'        => [],
      'mkdir'      => ['stdapi_fs_mkdir'],
      'pwd'        => ['stdapi_fs_getwd'],
      'rmdir'      => ['stdapi_fs_delete_dir'],
      'rm'         => ['stdapi_fs_delete_file'],
      'mv'         => ['stdapi_fs_file_move'],
      'cp'         => ['stdapi_fs_file_copy'],
      'chmod'      => ['stdapi_fs_chmod'],
      'search'     => ['stdapi_fs_search'],
      'upload'     => [],
      'show_mount' => ['stdapi_fs_mount_show'],
    }

    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Stdapi: File system"
  end

  #
  # Search for files.
  #
  def cmd_search(*args)

    root    = nil
    recurse = true
    globs   = []
    files   = []

    opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-d" => [ true,  "The directory/drive to begin searching from. Leave empty to search all drives. (Default: #{root})" ],
      "-f" => [ true,  "A file pattern glob to search for. (e.g. *secret*.doc?)" ],
      "-r" => [ true,  "Recursivly search sub directories. (Default: #{recurse})" ]
    )

    opts.parse(args) { | opt, idx, val |
      case opt
        when "-h"
          print_line("Usage: search [-d dir] [-r recurse] -f pattern [-f pattern]...")
          print_line("Search for files.")
          print_line(opts.usage)
          return
        when "-d"
          root = val
        when "-f"
          globs << val
        when "-r"
          recurse = false if val =~ /^(f|n|0)/i
      end
    }

    if globs.empty?
      print_error("You must specify a valid file glob to search for, e.g. >search -f *.doc")
      return
    end

    globs.uniq.each do |glob|
      files += client.fs.file.search(root, glob, recurse)
    end

    if files.empty?
      print_line("No files matching your search were found.")
      return
    end

    print_line("Found #{files.length} result#{ files.length > 1 ? 's' : '' }...")
    files.each do | file |
      if file['size'] > 0
        print("    #{file['path']}#{ file['path'].empty? ? '' : client.fs.file.separator }#{file['name']} (#{file['size']} bytes)\n")
      else
        print("    #{file['path']}#{ file['path'].empty? ? '' : client.fs.file.separator }#{file['name']}\n")
      end
    end

  end

  #
  # Show all the mount points/logical drives (currently geared towards
  # the Windows Meterpreter).
  #
  def cmd_show_mount(*args)
    if args.include?('-h')
      print_line('Usage: show_mount')
      return true
    end

    mounts = client.fs.mount.show_mount

    table = Rex::Text::Table.new(
      'Header'    => 'Mounts / Drives',
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => [
        'Name', 'Type', 'Size (Total)', 'Size (Free)', 'Mapped to'
      ]
    )

    mounts.each do |d|
      ts = ::Filesize.from("#{d[:total_space]} B").pretty.split(' ')
      fs = ::Filesize.from("#{d[:free_space]} B").pretty.split(' ')
      table << [
        d[:name],
        d[:type],
        "#{ts[0].rjust(6)} #{ts[1].ljust(3)}",
        "#{fs[0].rjust(6)} #{fs[1].ljust(3)}",
        d[:unc]
      ]
    end

    print_line
    print_line(table.to_s)
    print_line
    print_line("Total mounts/drives: #{mounts.length}")
    print_line
  end

  #
  # Reads the contents of a file and prints them to the screen.
  #
  def cmd_cat(*args)
    if (args.length == 0)
      print_line("Usage: cat file")
      return true
    end

    if (client.fs.file.stat(args[0]).directory?)
      print_error("#{args[0]} is a directory")
    else
      fd = client.fs.file.new(args[0], "rb")
      begin
        until fd.eof?
          print(fd.read)
        end
      # EOFError is raised if file is empty, do nothing, just catch
      rescue EOFError
      end
      fd.close
    end

    true
  end

  #
  # Tab completion for the cat command
  #
  def cmd_cat_tabs(str, words)
    tab_complete_cfilenames(str, words)
  end

  #
  # Change the working directory.
  #
  def cmd_cd(*args)
    if (args.length == 0)
      print_line("Usage: cd directory")
      return true
    end
    if args[0] =~ PATH_EXPAND_REGEX
      client.fs.dir.chdir(client.fs.file.expand_path(args[0].upcase))
    else
      client.fs.dir.chdir(args[0])
    end

    return true
  end

  #
  # Tab completion for the cd command
  #
  def cmd_cd_tabs(str, words)
    tab_complete_cdirectory(str, words)
  end

  #
  # Change the local working directory.
  #
  def cmd_lcd(*args)
    if (args.length == 0)
      print_line("Usage: lcd directory")
      return true
    end

    ::Dir.chdir(args[0])

    return true
  end

  #
  # Tab completion for the lcd command
  #
  def cmd_lcd_tabs(str, words)
    tab_complete_directory(str, words)
  end

  #
  # Retrieve the checksum of a file
  #
  def cmd_checksum(*args)
    algorithm = args.shift
    algorithm.downcase! unless algorithm.nil?
    unless args.length > 0 and CHECKSUM_ALGORITHMS.include?(algorithm)
      print_line("Usage: checksum [#{ CHECKSUM_ALGORITHMS.join(' / ') }] file1 file2 file3 ...")
      return true
    end

    args.each do |filepath|
      checksum = client.fs.file.send(algorithm, filepath)
      print_line("#{Rex::Text.to_hex(checksum, '')}  #{filepath}")
    end

    return true
  end

  def cmd_checksum_tabs(str, words)
    tabs = []
    return tabs unless words.length == 1

    CHECKSUM_ALGORITHMS.each do |algorithm|
      tabs << algorithm if algorithm.start_with?(str.downcase)
    end

    tabs
  end

  #
  # Delete the specified file(s).
  #
  def cmd_rm(*args)
    if (args.length == 0)
      print_line("Usage: rm file1 [file2...]")
      return true
    end

    args.each do |file_path|
      file_path = client.fs.file.expand_path(file_path) if file_path =~ PATH_EXPAND_REGEX
      client.fs.file.rm(file_path)
    end

    return true
  end

  alias :cmd_del :cmd_rm
  alias :cmd_rm_tabs :cmd_cat_tabs
  alias :cmd_del_tabs :cmd_cat_tabs

  #
  # Move source to destination
  #
  def cmd_mv(*args)
    if (args.length < 2)
      print_line("Usage: mv oldfile newfile")
      return true
    end
    old_path = args[0]
    old_path = client.fs.file.expand_path(old_path) if old_path =~ PATH_EXPAND_REGEX
    new_path = args[1]
    new_path = client.fs.file.expand_path(new_path) if new_path =~ PATH_EXPAND_REGEX
    client.fs.file.mv(old_path, new_path)
    return true
  end

  alias :cmd_move :cmd_mv
  alias :cmd_rename :cmd_mv
  alias :cmd_mv_tabs :cmd_cat_tabs
  alias :cmd_move_tabs :cmd_cat_tabs
  alias :cmd_rename_tabs :cmd_cat_tabs

  #
  # Move source to destination
  #
  def cmd_cp(*args)
    if (args.length < 2)
      print_line("Usage: cp oldfile newfile")
      return true
    end
    old_path = args[0]
    old_path = client.fs.file.expand_path(old_path) if old_path =~ PATH_EXPAND_REGEX
    new_path = args[1]
    new_path = client.fs.file.expand_path(new_path) if new_path =~ PATH_EXPAND_REGEX
    client.fs.file.cp(old_path, new_path)
    return true
  end

  alias :cmd_copy :cmd_cp
  alias :cmd_cp_tabs :cmd_cat_tabs
  alias :cmd_chmod_tabs :cmd_cat_tabs

  #
  # Change the permissions on a remote file
  #
  def cmd_chmod(*args)
    if (args.length != 2)
      print_line("Usage: chmod permission file")
      return true
    end
    file_path = args[1]
    file_path = client.fs.file.expand_path(file_path) if file_path =~ PATH_EXPAND_REGEX
    client.fs.file.chmod(file_path, args[0].to_i(8))
    return true
  end

  def cmd_download_help
    print_line("Usage: download [options] src1 src2 src3 ... destination")
    print_line
    print_line("Downloads remote files and directories to the local machine.")
    print_line(@@download_opts.usage)
  end

  #
  # Downloads a file or directory from the remote machine to the local
  # machine.
  #
  def cmd_download(*args)
    if (args.empty? or args.include? "-h")
      cmd_download_help
      return true
    end

    recursive = false
    src_items = []
    last      = nil
    dest      = nil
    continue  = false
    tries     = false
    tries_no  = 0
    opts      = {}

    @@download_opts.parse(args) { |opt, idx, val|
      case opt
      when "-a"
        opts['adaptive'] = true
      when "-b"
        opts['block_size'] = val.to_i
      when "-r"
        recursive = true
        opts['recursive'] = true
      when "-c"
        continue = true
        opts['continue'] = true
      when "-l"
        tries = true
        tries_no = val.to_i
        opts['tries'] = true
        opts['tries_no'] = tries_no
      when "-t"
        opts['timestamp'] = '_' + Time.now.iso8601
      when nil
        src_items << last if (last)
        last = val
      end
    }

    # No files given, nothing to do
    if not last
      cmd_download_help
      return true
    end

    # Source and destination will be the same
    if src_items.empty?
      src_items << last
      # Use the basename of the remote filename so we don't end up with
      # a file named c:\\boot.ini in linux
      dest = ::Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File.basename(last)
    else
      dest = last
    end

    # Download to a directory, not a pattern
    if client.fs.file.is_glob?(dest)
      dest = ::File.dirname(dest)
    end

    # Go through each source item and download them
    src_items.each { |src|
      glob = nil
      if client.fs.file.is_glob?(src)
        glob = ::File.basename(src)
        src = ::File.dirname(src)
      end

      # Use search if possible for recursive pattern matching. It will work
      # more intuitively since it will not try to match on intermediate
      # directories, only file names.
      if glob && recursive && client.commands.include?('stdapi_fs_search')

        files = client.fs.file.search(src, glob, recursive)
        if !files.empty?
          print_line("Downloading #{files.length} file#{files.length > 1 ? 's' : ''}...")

          files.each do |file|
            src_separator = client.fs.file.separator
            src_path = file['path'] + client.fs.file.separator + file['name']
            dest_path = ::File.join(dest, ::Rex::FileUtils::clean_path(file['path'].tr(src_separator, ::File::SEPARATOR)))

            client.fs.file.download(dest_path, src_path, opts) do |step, src, dst|
              print_status("#{step.ljust(11)}: #{src} -> #{dst}")
              client.framework.events.on_session_download(client, src, dest) if msf_loaded?
            end
          end

        else
          print_status("No matching files found for download")
        end

      else
        # Perform direct matching
        tries_cnt = 0
        begin
          stat = client.fs.file.stat(src)
        rescue Rex::TimeoutError
          if (tries && (tries_no == 0 || tries_cnt < tries_no))
            tries_cnt += 1
            print_error("Error opening: #{src} - retry (#{tries_cnt})")
            retry
          else
            print_error("Error opening: #{src} - giving up")
            raise
          end
        end

        if (stat.directory?)
          client.fs.dir.download(dest, src, opts, true, glob) do |step, src, dst|
            print_status("#{step.ljust(11)}: #{src} -> #{dst}")
            client.framework.events.on_session_download(client, src, dest) if msf_loaded?
          end
        elsif (stat.file?)
          client.fs.file.download(dest, src, opts) do |step, src, dst|
            print_status("#{step.ljust(11)}: #{src} -> #{dst}")
            client.framework.events.on_session_download(client, src, dest) if msf_loaded?
          end
        end
      end
    }

    true
  end

  def cmd_edit_help
    print_line('Edit a file on remote machine.')
    print_line("Usage: edit file")
    print_line
  end

  #
  # Downloads a file to a temporary file, spawns and editor, and then uploads
  # the contents to the remote machine after completion.
  #
  def cmd_edit(*args)
    if args.empty? || args.include?('-h')
      cmd_edit_help
      return true
    end

    # Get a temporary file path
    meterp_temp = Tempfile.new('meterp')
    meterp_temp.binmode
    temp_path = meterp_temp.path

    # Try to download the file, but don't worry if it doesn't exist
    client.fs.file.download_file(temp_path, args[0]) rescue nil

    # Spawn the editor (default to vi)
    editor = Rex::Compat.getenv('EDITOR') || 'vi'

    # If it succeeds, upload it to the remote side.
    if (system("#{editor} #{temp_path}") == true)
      client.fs.file.upload_file(args[0], temp_path)
    end

    # Get rid of that pesky temporary file
    ::File.delete(temp_path) rescue nil
  end

  alias :cmd_edit_tabs :cmd_cat_tabs

  #
  # Display the local working directory.
  #
  def cmd_lpwd(*args)
    print_line(::Dir.pwd)
    return true
  end

  alias cmd_getlwd cmd_lpwd


  def cmd_ls_help
    print_line "Usage: ls [options] [glob/path]"
    print_line
    print_line "Lists contents of directory or file info, searchable"
    print_line @@ls_opts.usage
  end

  def list_path(path, columns, sort, order, short, recursive = false, depth = 0, search_term = nil)

    # avoid infinite recursion
    if depth > 100
      return
    end

    tbl = Rex::Text::Table.new(
      'Header'  => "Listing: #{path}",
      'SortIndex' => columns.index(sort),
      'SortOrder' => order,
      'Columns' => columns,
      'SearchTerm' => search_term)

    items = 0

    # Enumerate each item...
    # No need to sort as Table will do it for us
    client.fs.dir.entries_with_info(path).each do |p|

      ffstat = p['StatBuf']
      fname = p['FileName'] || 'unknown'

      row = [
          ffstat ? ffstat.prettymode : '',
          ffstat ? ffstat.size       : '',
          ffstat ? ffstat.ftype[0,3] : '',
          ffstat ? ffstat.mtime      : '',
          fname
        ]
      row.insert(4, p['FileShortName'] || '') if short

      if fname != '.' && fname != '..'
        if row.join(' ') =~ /#{search_term}/
          tbl << row
          items += 1
        end

        if recursive && ffstat && ffstat.directory?
          if client.fs.file.is_glob?(path)
            child_path = ::File.dirname(path) + ::File::SEPARATOR + fname
            child_path += ::File::SEPARATOR + ::File.basename(path)
          else
            child_path = path + ::File::SEPARATOR + fname
          end
          begin
            list_path(child_path, columns, sort, order, short, recursive, depth + 1, search_term)
          rescue RequestError
          end
        end
      end
    end

    if items > 0
      print_line(tbl.to_s)
    else
      print_line("No entries exist in #{path}")
    end
  end

  #
  # Lists files
  #
  def cmd_ls(*args)
    # Set defaults
    path = client.fs.dir.getwd
    search_term = nil
    sort = 'Name'
    short = nil
    order = :forward
    recursive = nil

    # Parse the args
    @@ls_opts.parse(args) { |opt, idx, val|
      case opt
      # Sort options
      when '-s'
        sort = 'Size'
      when '-t'
        sort = 'Last modified'
      # Output options
      when '-x'
        short = true
      when '-l'
        short = nil
      when '-r'
        order = :reverse
      when '-R'
        recursive = true
      # Search
      when '-S'
        search_term = val
        if search_term.nil?
          print_error("Enter a search term")
          return true
        else
          search_term = /#{search_term}/nmi
        end
      # Help and path
      when "-h"
        cmd_ls_help
        return 0
      when nil
        path = val
      end
    }

    columns = [ 'Mode', 'Size', 'Type', 'Last modified', 'Name' ]
    columns.insert(4, 'Short Name') if short

    stat_path = path

    # Check session capabilities
    is_glob = client.fs.file.is_glob?(path)
    if is_glob
      if !client.commands.include?('stdapi_fs_search')
        print_line('File globbing not supported with this session')
        return
      end
      stat_path = ::File.dirname(path)
    end

    stat = client.fs.file.stat(stat_path)
    if stat.directory?
      list_path(path, columns, sort, order, short, recursive, 0, search_term)
    else
      print_line("#{stat.prettymode}  #{stat.size}  #{stat.ftype[0,3]}  #{stat.mtime}  #{path}")
    end

    return true
  end

  #
  # Tab completion for the ls command
  #
  def cmd_ls_tabs(str, words)
    tab_complete_cdirectory(str, words)
  end

  #
  # Alias the ls command to dir, for those of us who have windows muscle-memory
  #
  alias :cmd_dir :cmd_ls
  alias :cmd_dir_help :cmd_ls_help
  alias :cmd_dir_tabs :cmd_ls_tabs

  def cmd_lls_help
    print_line "Usage: lls [options]"
    print_line
    print_line "Lists contents of a local directory or file info"
    print_line @@lls_opts.usage
  end

  #
  # Get list local path information for lls command
  #
  def list_local_path(path, sort, order, search_term = nil)
    # Single file as path
    if !::File.directory?(path)
      perms = pretty_perms(path)
      stat = ::File.stat(path)
      print_line("#{perms}  #{stat.size}  #{stat.ftype[0,3]}  #{stat.mtime}  #{path}")
      return
    end

    # Enumerate each item...
    # No need to sort as Table will do it for us
    columns = [ 'Mode', 'Size', 'Type', 'Last modified', 'Name' ]
    tbl = Rex::Text::Table.new(
      'Header'  => "Listing Local: #{path}",
      'SortIndex' => columns.index(sort),
      'SortOrder' => order,
      'Columns' => columns)

    items = 0
    files = ::Dir.entries(path)

    files.each do |file|
      file_path = ::File.join(path, file)

      perms = pretty_perms(file_path)
      stat = ::File.stat(file_path)

      row = [
        perms ? perms                : '',
        stat.size ? stat.size.to_s   : '',
        stat.ftype ? stat.ftype[0,3] : '',
        stat.mtime ? stat.mtime      : '',
        file
      ]
      if file != '.' && file != '..'
        if row.join(' ') =~ /#{search_term}/
          tbl << row
          items += 1
        end
      end
    end
    if items > 0
      print_line(tbl.to_s)
    else
      print_line("No entries exist in #{path}")
    end
  end

  # Code from prettymode in lib/rex/post/file_stat.rb
  # adapted for local file usage
  def pretty_perms(path)
    m  = ::File.stat(path).mode
    om = '%04o' % m
    perms = ''

    3.times {
      perms = ((m & 01) == 01 ? 'x' : '-') + perms
      perms = ((m & 02) == 02 ? 'w' : '-') + perms
      perms = ((m & 04) == 04 ? 'r' : '-') + perms
      m >>= 3
    }

    return "#{om}/#{perms}"
  end

  #
  # List local files
  #
  def cmd_lls(*args)
    # Set Defaults
    path = ::Dir.pwd
    sort = 'Name'
    order = :forward
    search_term = nil

    # Parse the args
    @@lls_opts.parse(args) { |opt, idx, val|
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
          print_error("Enter a search term")
          return true
        else
          search_term = /#{search_term}/nmi
        end
      # Help and path
      when "-h"
        cmd_lls_help
        return 0
      when nil
        path = val
      end
    }

    list_local_path(path, sort, order, search_term)
  end

  alias :cmd_lls_tabs :cmd_lcd_tabs

  #
  # Alias the lls command to dir, for those of us who have windows muscle-memory
  #
  alias :cmd_ldir :cmd_lls

  #
  # Make one or more directory.
  #
  def cmd_mkdir(*args)
    if (args.length == 0)
      print_line("Usage: mkdir dir1 dir2 dir3 ...")
      return true
    end

    args.each { |dir_path|
      dir_path = client.fs.file.expand_path(dir_path) if dir_path =~ PATH_EXPAND_REGEX
      print_line("Creating directory: #{dir_path}")
      client.fs.dir.mkdir(dir_path)
    }

    return true
  end

  alias :cmd_mkdir_tabs :cmd_cd_tabs

  #
  # Display the working directory.
  #
  def cmd_pwd(*args)
    print_line(client.fs.dir.getwd)
  end

  alias cmd_getwd cmd_pwd

  #
  # Removes one or more directory if it's empty.
  #
  def cmd_rmdir(*args)
    if (args.length == 0 or args.include?("-h"))
      print_line("Usage: rmdir dir1 dir2 dir3 ...")
      return true
    end

    args.each { |dir_path|
      dir_path = client.fs.file.expand_path(dir_path) if dir_path =~ PATH_EXPAND_REGEX
      print_line("Removing directory: #{dir_path}")
      client.fs.dir.rmdir(dir_path)
    }

    return true
  end

  alias :cmd_rmdir_tabs :cmd_cd_tabs

  def cmd_upload_help
    print_line("Usage: upload [options] src1 src2 src3 ... destination")
    print_line
    print_line("Uploads local files and directories to the remote machine.")
    print_line(@@upload_opts.usage)
  end

  #
  # Uploads a file or directory to the remote machine from the local
  # machine.
  #
  def cmd_upload(*args)
    if (args.empty? or args.include?("-h"))
      cmd_upload_help
      return true
    end

    recursive = false
    src_items = []
    last      = nil
    dest      = nil

    @@upload_opts.parse(args) { |opt, idx, val|
      case opt
        when "-r"
          recursive = true
        when nil
          if (last)
            src_items << last
          end

          last = val
      end
    }

    return true if not last

    # Source and destination will be the same
    src_items << last if src_items.empty?

    if args.size == 1
      dest = last.split(/(\/|\\)/).last
    else
      dest = last
    end

    # Go through each source item and upload them
    src_items.each { |src|
      stat = ::File.stat(src)

      if (stat.directory?)
        client.fs.dir.upload(dest, src, recursive) { |step, src, dst|
          print_status("#{step.ljust(11)}: #{src} -> #{dst}")
          client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
        }
      elsif (stat.file?)
        if client.fs.file.exist?(dest) && client.fs.file.stat(dest).directory?
          client.fs.file.upload(dest, src) { |step, src, dst|
            print_status("#{step.ljust(11)}: #{src} -> #{dst}")
            client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
          }
        else
          client.fs.file.upload_file(dest, src) { |step, src, dst|
            print_status("#{step.ljust(11)}: #{src} -> #{dst}")
            client.framework.events.on_session_upload(client, src, dest) if msf_loaded?
          }
        end
      end
    }

    return true
  end

  def cmd_upload_tabs(str, words)
    return [] if words.length > 1

    tab_complete_filenames(str, words)
  end

  #
  # Provide a generic tab completion for client file names.
  # This tab complete method would create request to the client, so
  # sometimes it wouldn't execute successfully especailly on bad network.
  #
  def tab_complete_cfilenames(str, words)
    if client.commands.include?('stdapi_fs_ls')
      return client.fs.dir.match(str) rescue nil
    end

    []
  end

  #
  # Provide a generic tab completion for client directory names.
  #
  def tab_complete_cdirectory(str, words)
    if client.commands.include?('stdapi_fs_ls')
      return client.fs.dir.match(str, true) rescue nil
    end

    []
  end

end

end
end
end
end
