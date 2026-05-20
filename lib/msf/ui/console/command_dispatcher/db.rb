# -*- coding: binary -*-

require 'json'
require 'rexml/document'
require 'metasploit/framework/data_service'
require 'metasploit/framework/data_service/remote/http/core'

module Msf
module Ui
module Console
module CommandDispatcher

class Db

  require 'tempfile'

  include Msf::Ui::Console::CommandDispatcher
  include Msf::Ui::Console::CommandDispatcher::Common
  include Msf::Ui::Console::CommandDispatcher::Db::Common
  include Msf::Ui::Console::CommandDispatcher::Db::Analyze
  include Msf::Ui::Console::CommandDispatcher::Db::Klist
  include Msf::Ui::Console::CommandDispatcher::Db::Certs

  DB_CONFIG_PATH = 'framework/database'

  #
  # The dispatcher's name.
  #
  def name
    "Database Backend"
  end

  #
  # Returns the hash of commands supported by this dispatcher.
  #
  def commands
    base = {
      "db_connect"       => "Connect to an existing data service",
      "db_disconnect"    => "Disconnect from the current data service",
      "db_status"        => "Show the current data service status",
      "db_save"          => "Save the current data service connection as the default to reconnect on startup",
      "db_remove"        => "Remove the saved data service entry"
    }

    more = {
      "workspace"     => "Switch between database workspaces",
      "hosts"         => "List all hosts in the database",
      "services"      => "List all services in the database",
      "vulns"         => "List all vulnerabilities in the database",
      "notes"         => "List all notes in the database",
      "loot"          => "List all loot in the database",
      "klist"         => "List Kerberos tickets in the database",
      "certs"         => "List Pkcs12 certificate bundles in the database",
      "db_import"     => "Import a scan result file (filetype will be auto-detected)",
      "db_export"     => "Export a file containing the contents of the database",
      "db_nmap"       => "Executes nmap and records the output automatically",
      "db_rebuild_cache" => "Rebuilds the database-stored module cache (deprecated)",
      "analyze"       => "Analyze database information about a specific address or address range",
      "db_stats"         => "Show statistics for the database"
    }

    # Always include commands that only make sense when connected.
    # This avoids the problem of them disappearing unexpectedly if the
    # database dies or times out.  See #1923

    base.merge(more)
  end

  def deprecated_commands
    [
      "db_autopwn",
      "db_driver",
      "db_hosts",
      "db_notes",
      "db_services",
      "db_vulns",
    ]
  end

  #
  # Attempts to connect to the previously configured database, and additionally keeps track of
  # the currently loaded data service.
  #
  def load_config(path = nil)
    result = Msf::DbConnector.db_connect_from_config(framework, path)

    if result[:error]
      print_error(result[:error])
    end
    if result[:data_service_name]
      @current_data_service = result[:data_service_name]
    end
  end

  @@workspace_opts = Rex::Parser::Arguments.new(
    [ '-h', '--help' ] => [ false, 'Help banner.'],
    [ '-a', '--add' ] => [ true, 'Add a workspace.', '<name>'],
    [ '-d', '--delete' ] => [ true, 'Delete a workspace.', '<name>'],
    [ '-D', '--delete-all' ] => [ false, 'Delete all workspaces.'],
    [ '-r', '--rename' ] => [ true, 'Rename a workspace.', '<old> <new>'],
    [ '-l', '--list' ] => [ false, 'List workspaces.'],
    [ '-v', '--list-verbose' ] => [ false, 'List workspaces verbosely.'],
    [ '-S', '--search' ] => [ true, 'Search for a workspace.', '<name>']
  )

  def cmd_workspace_help
    print_line "Usage:"
    print_line "    workspace          List workspaces"
    print_line "    workspace [name]   Switch workspace"
    print_line @@workspace_opts.usage
  end

  def cmd_workspace(*args)
    return unless active?

    state = :nil

    list = false
    verbose = false
    names = []
    search_term = nil

    @@workspace_opts.parse(args) do |opt, idx, val|
      case opt
      when '-h', '--help'
        cmd_workspace_help
        return
      when '-a', '--add'
        return cmd_workspace_help unless state == :nil

        state = :adding
        names << val if !val.nil?
      when '-d', '--del'
        return cmd_workspace_help unless state == :nil

        state = :deleting
        names << val if !val.nil?
      when '-D', '--delete-all'
        return cmd_workspace_help unless state == :nil

        state = :delete_all
      when '-r', '--rename'
        return cmd_workspace_help unless state == :nil

        state = :renaming
        names << val if !val.nil?
      when '-v', '--verbose'
        verbose = true
      when '-l', '--list'
        list = true
      when '-S', '--search'
        search_term = val
      else
        names << val if !val.nil?
      end
    end

    if state == :adding and names
      # Add workspaces
      wspace = nil
      names.each do |name|
        wspace = framework.db.workspaces(name: name).first
        if wspace
          print_status("Workspace '#{wspace.name}' already existed, switching to it.")
        else
          wspace = framework.db.add_workspace(name)
          print_status("Added workspace: #{wspace.name}")
        end
      end
      framework.db.workspace = wspace
      print_status("Workspace: #{framework.db.workspace.name}")
    elsif state == :deleting and names
      ws_ids_to_delete = []
      starting_ws = framework.db.workspace
      names.uniq.each do |n|
        ws = framework.db.workspaces(name: n).first
        ws_ids_to_delete << ws.id if ws
      end
      if ws_ids_to_delete.count > 0
        deleted = framework.db.delete_workspaces(ids: ws_ids_to_delete)
        process_deleted_workspaces(deleted, starting_ws)
      else
        print_status("No workspaces matching the given name(s) were found.")
      end
    elsif state == :delete_all
      ws_ids_to_delete = []
      starting_ws = framework.db.workspace
      framework.db.workspaces.each do |ws|
        ws_ids_to_delete << ws.id
      end
      deleted = framework.db.delete_workspaces(ids: ws_ids_to_delete)
      process_deleted_workspaces(deleted, starting_ws)
    elsif state == :renaming
      if names.length != 2
        print_error("Wrong number of arguments to rename")
        return
      end

      ws_to_update = framework.db.find_workspace(names.first)
      unless ws_to_update
        print_error("Workspace '#{names.first}' does not exist")
        return
      end
      opts = {
          id: ws_to_update.id,
          name: names.last
      }
      begin
        updated_ws = framework.db.update_workspace(opts)
        if updated_ws
          framework.db.workspace = updated_ws if names.first == framework.db.workspace.name
          print_status("Renamed workspace '#{names.first}' to '#{updated_ws.name}'")
        else
          print_error "There was a problem updating the workspace. Setting to the default workspace."
          framework.db.workspace = framework.db.default_workspace
          return
        end
        if names.first == Msf::DBManager::Workspace::DEFAULT_WORKSPACE_NAME
          print_status("Recreated default workspace")
        end
      rescue => e
        print_error "Failed to rename workspace: #{e.message}"
      end

    elsif !names.empty?
      name = names.last
      # Switch workspace
      workspace = framework.db.find_workspace(name)
      if workspace
        framework.db.workspace = workspace
        print_status("Workspace: #{workspace.name}")
      else
        print_error("Workspace not found: #{name}")
        return
      end
    else
      current_workspace = framework.db.workspace

      unless verbose
        current = nil
        framework.db.workspaces.sort_by {|s| s.name}.each do |s|
          if s.name == current_workspace.name
            current = s.name
          else
            print_line("  #{s.name}")
          end
        end
        print_line("%red* #{current}%clr") unless current.nil?
        return
      end
      col_names = %w{current name hosts services vulns creds loots notes}

      tbl = Rex::Text::Table.new(
        'Header'     => 'Workspaces',
        'Columns'    => col_names,
        'SortIndex'  => -1,
        'SearchTerm' => search_term
      )

      framework.db.workspaces.each do |ws|
        tbl << [
          current_workspace.name == ws.name ? '*' : '',
          ws.name,
          framework.db.hosts(workspace: ws.name).count,
          framework.db.services(workspace: ws.name).count,
          framework.db.vulns(workspace: ws.name).count,
          framework.db.creds(workspace: ws.name).count,
          framework.db.loots(workspace: ws.name).count,
          framework.db.notes(workspace: ws.name).count
        ]
      end

      print_line
      print_line(tbl.to_s)
    end
  end

  def process_deleted_workspaces(deleted_workspaces, starting_ws)
    deleted_workspaces.each do |ws|
      print_status "Deleted workspace: #{ws.name}"
      if ws.name == Msf::DBManager::Workspace::DEFAULT_WORKSPACE_NAME
        framework.db.workspace = framework.db.default_workspace
        print_status 'Recreated the default workspace'
      elsif ws == starting_ws
        framework.db.workspace = framework.db.default_workspace
        print_status "Switched to workspace: #{framework.db.workspace.name}"
      end
    end
  end

  def cmd_workspace_tabs(str, words)
    return [] unless active?
    framework.db.workspaces.map(&:name) if (words & ['-a','--add']).empty?
  end

  #
  # Tab completion for the hosts command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_hosts_tabs(str, words)
    if words.length == 1
      return @@hosts_opts.option_keys.select { |opt| opt.start_with?(str) }
    end

    case words[-1]
    when '-c', '--columns', '-C', '--columns-until-restart'
      return @@hosts_columns
    when '-o', '--output'
      return tab_complete_filenames(str, words)
    end

    if @@hosts_opts.arg_required?(words[-1])
      return []
    end

    return @@hosts_opts.option_keys.select { |opt| opt.start_with?(str) }
  end

  def cmd_hosts_help
    # This command does some lookups for the list of appropriate column
    # names, so instead of putting all the usage stuff here like other
    # help methods, just use it's "-h" so we don't have to recreating
    # that list
    cmd_hosts("-h")
  end

  # Changes the specified host data
  #
  # @param host_ranges - range of hosts to process
  # @param host_data - hash of host data to be updated
  def change_host_data(host_ranges, host_data)
    if !host_data || host_data.length != 1
      print_error("A single key-value data hash is required to change the host data")
      return
    end
    attribute = host_data.keys[0]

    if host_ranges == [nil]
      print_error("In order to change the host #{attribute}, you must provide a range of hosts")
      return
    end

    each_host_range_chunk(host_ranges) do |host_search|
      next if host_search && host_search.empty?

      framework.db.hosts(address: host_search).each do |host|
        framework.db.update_host(host_data.merge(id: host.id))
        framework.db.report_note(host: host.address, type: "host.#{attribute}", data: { :host_data => host_data[attribute] })
      end
    end
  end

  def add_host_tag(rws, tag_name)
    if rws == [nil]
      print_error("In order to add a tag, you must provide a range of hosts")
      return
    end

    opts = Hash.new()
    opts[:workspace] = framework.db.workspace
    opts[:tag_name] = tag_name

    rws.each do |rw|
      rw.each do |ip|
        opts[:address] = ip
        unless framework.db.add_host_tag(opts)
          print_error("Host #{ip} could not be found.")
        end
      end
    end
  end

  def find_host_tags(workspace, host_id)
    opts = Hash.new()
    opts[:workspace] = workspace
    opts[:id] = host_id

    framework.db.get_host_tags(opts)
  end

  def delete_host_tag(rws, tag_name)
    opts = Hash.new()
    opts[:workspace] = framework.db.workspace
    opts[:tag_name] = tag_name

    # This will be the case if no IP was passed in, and we are just trying to delete all
    # instances of a given tag within the database.
    if rws == [nil]
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
      wspace.hosts.each do |host|
        opts[:address] = host.address
        framework.db.delete_host_tag(opts)
      end
    else
      rws.each do |rw|
        rw.each do |ip|
          opts[:address] = ip
          unless framework.db.delete_host_tag(opts)
            print_error("Host #{ip} could not be found.")
          end
        end
      end
    end
  end

  @@hosts_columns = [ 'address', 'mac', 'name', 'os_name', 'os_flavor', 'os_sp', 'purpose', 'info', 'comments']

  @@hosts_opts = Rex::Parser::Arguments.new(
    [ '-h', '--help' ] => [ false, 'Show this help information' ],
    [ '-a', '--add' ] => [ true, 'Add the hosts instead of searching', '<host>' ],
    [ '-u', '--up' ] => [ false, 'Only show hosts which are up' ],
    [ '-R', '--rhosts' ] => [ false, 'Set RHOSTS from the results of the search' ],
    [ '-S', '--search' ] => [ true, 'Search string to filter by', '<filter>' ],
    [ '-i', '--info' ] => [ true, 'Change the info of a host', '<info>' ],
    [ '-n', '--name' ] => [ true, 'Change the name of a host', '<name>' ],
    [ '-m', '--comment' ] => [ true, 'Change the comment of a host', '<comment>' ],
    [ '-t', '--tag' ] => [ true, 'Add or specify a tag to a range of hosts', '<tag>' ],
    [ '-T', '--delete-tag' ] => [ true, 'Remove a tag from a range of hosts', '<tag>' ],
    [ '-d', '--delete' ] => [ true, 'Delete the hosts instead of searching', '<hosts>' ],
    [ '-o', '--output' ] => [ true, 'Send output to a file in csv format', '<filename>' ],
    [ '-O', '--order' ] => [ true, 'Order rows by specified column number', '<column id>' ],
    [ '-c', '--columns' ] => [ true, 'Only show the given columns (see list below)', '<columns>' ],
    [ '-C', '--columns-until-restart' ] => [ true, 'Only show the given columns until the next restart (see list below)', '<columns>' ],
  )

  def cmd_hosts(*args)
    return unless active?
    onlyup = false
    set_rhosts = false
    mode = []
    delete_count = 0

    rhosts = []
    host_ranges = []
    search_term = nil

    order_by = nil
    info_data = nil
    name_data = nil
    comment_data = nil
    tag_name = nil

    output = nil
    default_columns = [
        'address',
        'arch',
        'comm',
        'comments',
        'created_at',
        'cred_count',
        'detected_arch',
        'exploit_attempt_count',
        'host_detail_count',
        'info',
        'mac',
        'name',
        'note_count',
        'os_family',
        'os_flavor',
        'os_lang',
        'os_name',
        'os_sp',
        'purpose',
        'scope',
        'service_count',
        'state',
        'updated_at',
        'virtual_host',
        'vuln_count',
        'workspace_id']

    default_columns << 'tags' # Special case
    virtual_columns = [ 'svcs', 'vulns', 'workspace', 'tags' ]

    col_search = @@hosts_columns

    default_columns.delete_if {|v| (v[-2,2] == "id")}
    @@hosts_opts.parse(args) do |opt, idx, val|
      case opt
      when '-h', '--help'
        print_line "Usage: hosts [ options ] [addr1 addr2 ...]"
        print_line
        print @@hosts_opts.usage
        print_line
        print_line "Available columns: #{default_columns.join(", ")}"
        print_line
        return
      when '-a', '--add'
        mode << :add
        arg_host_range(val, host_ranges)
      when '-d', '--delete'
        mode << :delete
        arg_host_range(val, host_ranges)
      when '-u', '--up'
        onlyup = true
      when '-o'
        output = val
        output = ::File.expand_path(output)
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = val
      when '-i', '--info'
        mode << :new_info
        info_data = val
      when '-n', '--name'
        mode << :new_name
        name_data = val
      when '-m', '--comment'
        mode << :new_comment
        comment_data = val
      when '-t', '--tag'
        mode << :tag
        tag_name = val
      when '-T', '--delete-tag'
        mode << :delete_tag
        tag_name = val
      when '-c', '-C'
        list = val
        if(!list)
          print_error("Invalid column list")
          return
        end
        col_search = list.strip().split(",")
        col_search.each { |c|
          if not default_columns.include?(c) and not virtual_columns.include?(c)
            all_columns = default_columns + virtual_columns
            print_error("Invalid column list. Possible values are (#{all_columns.join("|")})")
            return
          end
        }
        if opt == '-C'
          @@hosts_columns = col_search
        end
      when '-O'
        if (order_by = val.to_i - 1) < 0
          print_error('Please specify a column number starting from 1')
          return
        end
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(val, host_ranges))
          return
        end
      end
    end

    if col_search
      col_names = col_search
    else
      col_names = default_columns + virtual_columns
    end

    mode << :search if mode.empty?

    if mode == [:add]
      host_ranges.each do |range|
        range.each do |address|
          host = framework.db.find_or_create_host(:host => address)
          print_status("Time: #{host.created_at} Host: host=#{host.address}")
        end
      end
      return
    end

    cp_hsh = {}
    col_names.map do |col|
      cp_hsh[col] = { 'MaxChar' => 52 }
    end
    # If we got here, we're searching.  Delete implies search
    tbl = Rex::Text::Table.new(
      {
        'Header'  => "Hosts",
        'Columns' => col_names,
        'ColProps' => cp_hsh,
        'SortIndex' => order_by
      })

    # Sentinel value meaning all
    host_ranges.push(nil) if host_ranges.empty?

    case
    when mode == [:new_info]
        change_host_data(host_ranges, info: info_data)
      return
    when mode == [:new_name]
        change_host_data(host_ranges, name: name_data)
      return
    when mode == [:new_comment]
        change_host_data(host_ranges, comments: comment_data)
      return
    when mode == [:tag]
      begin
        add_host_tag(host_ranges, tag_name)
      rescue => e
        if e.message.include?('Validation failed')
          print_error(e.message)
        else
          raise e
        end
      end
      return
    when mode == [:delete_tag]
      begin
        delete_host_tag(host_ranges, tag_name)
      rescue => e
        if e.message.include?('Validation failed')
          print_error(e.message)
        else
          raise e
        end
      end
      return
    end

    matched_host_ids = []
    each_host_range_chunk(host_ranges) do |host_search|
      next if host_search && host_search.empty?

      framework.db.hosts(address: host_search, non_dead: onlyup, search_term: search_term).each do |host|
        matched_host_ids << host.id
        columns = col_names.map do |n|
          # Deal with the special cases
          if virtual_columns.include?(n)
            case n
            when "svcs";      host.service_count
            when "vulns";     host.vuln_count
            when "workspace"; host.workspace.name
            when "tags"
              found_tags = find_host_tags(framework.db.workspace, host.id)
              tag_names = found_tags.map(&:name).join(', ')
              tag_names
            end
          # Otherwise, it's just an attribute
          else
            host[n] || ""
          end
        end

        tbl << columns
        if set_rhosts
          addr = (host.scope.to_s != "" ? host.address + '%' + host.scope : host.address)
          rhosts << addr
        end
      end

      if mode == [:delete]
        result = framework.db.delete_host(ids: matched_host_ids)
        delete_count += result.size
      end
    end

    if output
      print_status("Wrote hosts to #{output}")
      ::File.open(output, "wb") { |ofd|
        ofd.write(tbl.to_csv)
      }
    else
      print_line
      print_line(tbl.to_s)
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

    print_status("Deleted #{delete_count} hosts") if delete_count > 0
  end

  #
  # Tab completion for the services command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_services_tabs(str, words)
    if words.length == 1
      return @@services_opts.option_keys.select { |opt| opt.start_with?(str) }
    end

    case words[-1]
    when '-c', '--column'
      return @@services_columns
    when '-O', '--order'
      return []
    when '-o', '--output'
      return tab_complete_filenames(str, words)
    when '-p', '--port'
      return []
    when '-r', '--protocol'
      return []
    end

    []
  end

  def cmd_services_help
    print_line "Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]"
    print_line
    print @@services_opts.usage
    print_line
    print_line "Available columns: #{@@services_columns.join(", ")}"
    print_line
  end

  @@services_columns = [ 'created_at', 'info', 'name', 'port', 'proto', 'state', 'updated_at' ]

  @@services_opts = Rex::Parser::Arguments.new(
    [ '-a', '--add' ] => [ false, 'Add the services instead of searching.' ],
    [ '-d', '--delete' ] => [ false, 'Delete the services instead of searching.' ],
    [ '-U', '--update' ] => [ false, 'Update data for existing service.' ],
    [ '-u', '--up' ] => [ false, 'Only show services which are up.' ],
    [ '-c', '--column' ] => [ true, 'Only show the given columns.', '<col1,col2>' ],
    [ '-p', '--port' ] => [ true, 'Search for a list of ports.', '<ports>' ],
    [ '-r', '--protocol' ] => [ true, 'Protocol type of the service being added [tcp|udp].', '<protocol>' ],
    [ '-s', '--name' ] => [ true, 'Name of the service to add.', '<name>' ],
    [ '-o', '--output' ] => [ true, 'Send output to a file in csv format.', '<filename>' ],
    [ '-O', '--order' ] => [ true, 'Order rows by specified column number.', '<column id>' ],
    [ '-R', '--rhosts' ] => [ false, 'Set RHOSTS from the results of the search.' ],
    [ '-S', '--search' ] => [ true, 'Search string to filter by.', '<filter>' ],
    [ '-h', '--help' ] => [ false, 'Show this help information.' ]
  )

  def db_connection_info(framework)
    unless framework.db.connection_established?
      return "#{framework.db.driver} selected, no connection"
    end

    cdb = ''
    if framework.db.driver == 'http'
      cdb = framework.db.name
    else
      ::ApplicationRecord.connection_pool.with_connection do |conn|
        if conn.respond_to?(:current_database)
          cdb = conn.current_database
        end
      end
    end

    if cdb.empty?
      output = "Connected Database Name could not be extracted. DB Connection type: #{framework.db.driver}."
    else
      output = "Connected to #{cdb}. Connection type: #{framework.db.driver}."
    end

    output
  end

  def cmd_db_stats(*args)
    return unless active?
    print_line "Session Type: #{db_connection_info(framework)}"

    current_workspace = framework.db.workspace
    example_workspaces = ::Mdm::Workspace.order(id: :desc)
    ordered_workspaces = ([current_workspace] + example_workspaces).uniq.sort_by(&:id)

    tbl = Rex::Text::Table.new(
    'Indent'  => 2,
    'Header'  => "Database Stats",
    'Columns' =>
      [
        "IsTarget",
        "ID",
        "Name",
        "Hosts",
        "Services",
        "Services per Host",
        "Vulnerabilities",
        "Vulns per Host",
        "Notes",
        "Creds",
        "Kerberos Cache"
      ],
    'SortIndex' => 1,
    'ColProps' => {
      'IsTarget' => {
        'Stylers' => [Msf::Ui::Console::TablePrint::RowIndicatorStyler.new],
        'ColumnStylers' => [Msf::Ui::Console::TablePrint::OmitColumnHeader.new],
        'Width' => 2
      }
    }
    )

    total_hosts = 0
    total_services = 0
    total_vulns = 0
    total_notes = 0
    total_creds = 0
    total_tickets = 0

    ordered_workspaces.map do |workspace|

      hosts = workspace.hosts.count
      services = workspace.services.count
      vulns = workspace.vulns.count
      notes = workspace.notes.count
      creds = framework.db.creds(workspace: workspace.name).count # workspace.creds.count.to_fs(:delimited) is always 0 for whatever reason
      kerbs = ticket_search([nil], nil, :workspace => workspace).count

      total_hosts += hosts
      total_services += services
      total_vulns += vulns
      total_notes += notes
      total_creds += creds
      total_tickets += kerbs

      tbl << [
        current_workspace.id == workspace.id,
        workspace.id,
        workspace.name,
        hosts.to_fs(:delimited),
        services.to_fs(:delimited),
        hosts > 0 ? (services.to_f / hosts).truncate(2) : 0,
        vulns.to_fs(:delimited),
        hosts > 0 ? (vulns.to_f / hosts).truncate(2) : 0,
        notes.to_fs(:delimited),
        creds.to_fs(:delimited),
        kerbs.to_fs(:delimited)
      ]
    end

    # total row
    tbl << [
      "",
      "Total",
      ordered_workspaces.length.to_fs(:delimited),
      total_hosts.to_fs(:delimited),
      total_services.to_fs(:delimited),
      total_hosts > 0 ? (total_services.to_f / total_hosts).truncate(2) : 0,
      total_vulns,
      total_hosts > 0 ? (total_vulns.to_f / total_hosts).truncate(2) : 0,
      total_notes,
      total_creds.to_fs(:delimited),
      total_tickets.to_fs(:delimited)
    ]

    print_line tbl.to_s
  end

  def cmd_services(*args)
    return unless active?
    mode = :search
    onlyup = false
    output_file = nil
    set_rhosts = false
    col_search = ['port', 'proto', 'name', 'state', 'info']

    names = nil
    order_by = nil
    proto = nil
    host_ranges  = []
    port_ranges  = []
    rhosts       = []
    delete_count = 0
    search_term  = nil
    opts         = {}

    @@services_opts.parse(args) do |opt, idx, val|
      case opt
      when '-a', '--add'
        mode = :add
      when '-d', '--delete'
        mode = :delete
      when '-U', '--update'
        mode = :update
      when '-u', '--up'
        onlyup = true
      when '-c'
        list = val
        if(!list)
          print_error("Invalid column list")
          return
        end
        col_search = list.strip().split(",")
        col_search.each { |c|
          if not @@services_columns.include? c
            print_error("Invalid column list. Possible values are (#{@@services_columns.join("|")})")
            return
          end
        }
      when '-p'
        unless (arg_port_range(val, port_ranges, true))
          return
        end
      when '-r'
        proto = val
        if (!proto)
          print_status("Invalid protocol")
          return
        end
        proto = proto.strip
      when '-s'
        namelist = val
        if (!namelist)
          print_error("Invalid name list")
          return
        end
        names = namelist.strip().split(",")
      when '-o'
        output_file = val
        if (!output_file)
          print_error("Invalid output filename")
          return
        end
        output_file = ::File.expand_path(output_file)
      when '-O'
        if (order_by = val.to_i - 1) < 0
          print_error('Please specify a column number starting from 1')
          return
        end
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = val
        opts[:search_term] = search_term
      when '-h', '--help'
        cmd_services_help
        return
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(val, host_ranges))
          return
        end
      end
    end

    ports = port_ranges.flatten.uniq

    if mode == :add
      # Can only deal with one port and one service name at a time
      # right now.  Them's the breaks.
      if ports.length != 1
        print_error("Exactly one port required")
        return
      end
      if host_ranges.empty?
        print_error("Host address or range required")
        return
      end
      host_ranges.each do |range|
        range.each do |addr|
          info = {
              :host => addr,
              :port => ports.first.to_i
          }
          info[:proto] = proto.downcase if proto
          info[:name]  = names.first.downcase if names and names.first

          svc = framework.db.find_or_create_service(info)
          print_status("Time: #{svc.created_at} Service: host=#{svc.host.address} port=#{svc.port} proto=#{svc.proto} name=#{svc.name}")
        end
      end
      return
    end

    # If we got here, we're searching.  Delete implies search
    col_names = @@services_columns
    if col_search
      col_names = col_search
    end
    tbl = Rex::Text::Table.new({
                                   'Header'    => "Services",
                                   'Columns'   => ['host'] + col_names,
                                   'SortIndex' => order_by
                               })

    # Sentinel value meaning all
    host_ranges.push(nil) if host_ranges.empty?
    ports = nil if ports.empty?
    matched_service_ids = []

    each_host_range_chunk(host_ranges) do |host_search|
      next if host_search && host_search.empty?
      opts[:workspace] = framework.db.workspace
      opts[:hosts] = {address: host_search} if !host_search.nil?
      opts[:port] = ports if ports
      framework.db.services(opts).each do |service|

        unless service.state == 'open'
          next if onlyup
        end

        host = service.host
        matched_service_ids << service.id

        if mode == :update
          service.name = names.first if names
          service.proto = proto if proto
          service.port = ports.first if ports
          framework.db.update_service(service.as_json.symbolize_keys)
        end

        columns = [host.address] + col_names.map { |n| service[n].to_s || "" }
        tbl << columns
        if set_rhosts
          addr = (host.scope.to_s != "" ? host.address + '%' + host.scope : host.address )
          rhosts << addr
        end
      end
    end

    if (mode == :delete)
      result = framework.db.delete_service(ids: matched_service_ids)
      delete_count += result.size
    end

    if (output_file == nil)
      print_line(tbl.to_s)
    else
      # create the output file
      ::File.open(output_file, "wb") { |f| f.write(tbl.to_csv) }
      print_status("Wrote services to #{output_file}")
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

    print_status("Deleted #{delete_count} services") if delete_count > 0

  end

  #
  # Tab completion for the vulns command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_vulns_tabs(str, words)
    if words.length == 1
      return @@vulns_opts.option_keys.select { |opt| opt.start_with?(str) }
    end
    case words[-1]
    when '-o', '--output'
      return tab_complete_filenames(str, words)
    end
  end

  def cmd_vulns_help
    print_line "Print all vulnerabilities in the database"
    print_line
    print_line "Usage: vulns [addr range]"
    print_line
    print @@vulns_opts.usage
    print_line
    print_line "Examples:"
    print_line "  vulns -p 1-65536          # only vulns with associated services"
    print_line "  vulns -p 1-65536 -s http  # identified as http on any port"
    print_line
  end

  @@vulns_opts = Rex::Parser::Arguments.new(
    [ '-h', '--help' ] => [ false, 'Show this help information.' ],
    [ '-o', '--output' ] => [ true, 'Send output to a file in csv format.', '<filename>' ],
    [ '-p', '--port' ] => [ true, 'List vulns matching this port spec.', '<port>' ],
    [ '-s', '--service' ] => [ true, 'List vulns matching these service names.', '<name>' ],
    [ '-R', '--rhosts' ] => [ false, 'Set RHOSTS from the results of the search.' ],
    [ '-S', '--search' ] => [ true, 'Search string to filter by.', '<filter>' ],
    [ '-i', '--info' ] => [ false, 'Display vuln information.' ],
    [ '-d', '--delete' ] => [ false, 'Delete vulnerabilities. Not officially supported.' ],
    [ '-v', '--verbose' ] => [ false, 'Display additional information.' ]
  )

  def cmd_vulns(*args)
    return unless active?

    default_columns = ['Timestamp', 'Host', 'Name', 'References']
    host_ranges = []
    port_ranges = []
    svcs        = []
    rhosts      = []

    search_term = nil
    show_info   = false
    show_vuln_attempts = false
    set_rhosts  = false
    output_file = nil
    delete_count = 0

    mode = nil

    @@vulns_opts.parse(args) do |opt, idx, val|
      case opt
      when '-d', '--delete' # TODO: This is currently undocumented because it's not officially supported.
        mode = :delete
      when '-h', '--help'
        cmd_vulns_help
        return
      when '-o', '--output'
        output_file = val
        if output_file
          output_file = File.expand_path(output_file)
        else
          print_error("Invalid output filename")
          return
        end
      when '-p', '--port'
        unless (arg_port_range(val, port_ranges, true))
          return
        end
      when '-s', '--service'
        service = val
        if (!service)
          print_error("Argument required for -s")
          return
        end
        svcs = service.split(/[\s]*,[\s]*/)
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = val
      when '-i', '--info'
        show_info = true
      when '-v', '--verbose'
        show_vuln_attempts = true
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(val, host_ranges))
          return
        end
      end
    end

    if show_info
      default_columns << 'Information'
    end

    # add sentinel value meaning all if empty
    host_ranges.push(nil) if host_ranges.empty?
    # normalize
    ports = port_ranges.flatten.uniq
    svcs.flatten!
    tbl = Rex::Text::Table.new(
        'Header' => 'Vulnerabilities',
        'Columns' => default_columns
    )

    matched_vuln_ids = []
    vulns = []
    if host_ranges.compact.empty?
      vulns = framework.db.vulns({:search_term => search_term})
    else
      each_host_range_chunk(host_ranges) do |host_search|
        next if host_search && host_search.empty?

        vulns.concat(framework.db.vulns({:hosts => { :address => host_search }, :search_term => search_term }))
      end
    end

    vulns.each do |vuln|
      reflist = vuln.refs.map {|r| r.name}
      if (vuln.service)
        # Skip this one if the user specified a port and it
        # doesn't match.
        next unless ports.empty? or ports.include? vuln.service.port
        # Same for service names
        next unless svcs.empty? or svcs.include?(vuln.service.name)
      else
        # This vuln has no service, so it can't match
        next unless ports.empty? and svcs.empty?
      end

      matched_vuln_ids << vuln.id

      row = []
      row << vuln.created_at
      row << vuln.host.address
      row << vuln.name
      row << reflist.join(',')
      if show_info
        row << vuln.info
      end
      tbl << row

      if set_rhosts
        addr = (vuln.host.scope.to_s != "" ? vuln.host.address + '%' + vuln.host.scope : vuln.host.address)
        rhosts << addr
      end
    end

    if mode == :delete
      result = framework.db.delete_vuln(ids: matched_vuln_ids)
      delete_count = result.size
    end

    if output_file
      if show_vuln_attempts
        print_warning("Cannot output to a file when verbose mode is enabled. Please remove verbose flag and try again.")
      else
        File.write(output_file, tbl.to_csv)
        print_status("Wrote vulnerability information to #{output_file}")
      end
    else
      print_line
      if show_vuln_attempts
        vulns_and_attempts = _format_vulns_and_vuln_attempts(vulns)
        _print_vulns_and_attempts(vulns_and_attempts)
      else
        print_line(tbl.to_s)
      end
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

    print_status("Deleted #{delete_count} vulnerabilities") if delete_count > 0
  end

  #
  # Tab completion for the notes command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_notes_tabs(str, words)
    if words.length == 1
      return @@notes_opts.option_keys.select { |opt| opt.start_with?(str) }
    end

    case words[-1]
    when '-O', '--order'
      return []
    when '-o', '--output'
      return tab_complete_filenames(str, words)
    end

    []
  end

  def cmd_notes_help
    print_line "Usage: notes [-h] [-t <type1,type2>] [-n <data string>] [-a] [addr range]"
    print_line
    print @@notes_opts.usage
    print_line
    print_line "Examples:"
    print_line "  notes --add -t apps -n 'winzip' 10.1.1.34 10.1.20.41"
    print_line "  notes -t smb.fingerprint 10.1.1.34 10.1.20.41"
    print_line "  notes -S 'nmap.nse.(http|rtsp)'"
    print_line
  end

  @@notes_opts = Rex::Parser::Arguments.new(
    [ '-a', '--add' ] => [ false, 'Add a note to the list of addresses, instead of listing.' ],
    [ '-d', '--delete' ] => [ false, 'Delete the notes instead of searching.' ],
    [ '-h', '--help' ] => [ false, 'Show this help information.' ],
    [ '-n', '--note' ] => [ true, 'Set the data for a new note (only with -a).', '<note>' ],
    [ '-O', '--order' ] => [ true, 'Order rows by specified column number.', '<column id>' ],
    [ '-o', '--output' ] => [ true, 'Save the notes to a csv file.', '<filename>' ],
    [ '-R', '--rhosts' ] => [ false, 'Set RHOSTS from the results of the search.' ],
    [ '-S', '--search' ] => [ true, 'Search string to filter by.', '<filter>' ],
    [ '-t', '--type' ] => [ true, 'Search for a list of types, or set single type for add.', '<type1,type2>' ],
    [ '-u', '--update' ] => [ false, 'Update a note. Not officially supported.' ]
  )

  def cmd_notes(*args)
    return unless active?
  ::ApplicationRecord.connection_pool.with_connection {
    mode = :search
    data = nil
    types = nil
    set_rhosts = false

    host_ranges = []
    rhosts      = []
    search_term = nil
    output_file = nil
    delete_count = 0
    order_by = nil

    @@notes_opts.parse(args) do |opt, idx, val|
      case opt
      when '-a', '--add'
        mode = :add
      when '-d', '--delete'
        mode = :delete
      when '-n', '--note'
        data = val
        if(!data)
          print_error("Can't make a note with no data")
          return
        end
      when '-t', '--type'
        typelist = val
        if(!typelist)
          print_error("Invalid type list")
          return
        end
        types = typelist.strip().split(",")
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = val
      when '-o', '--output'
        output_file = val
        output_file = ::File.expand_path(output_file)
      when '-O'
        if (order_by = val.to_i - 1) < 0
          print_error('Please specify a column number starting from 1')
          return
        end
      when '-u', '--update'  # TODO: This is currently undocumented because it's not officially supported.
        mode = :update
      when '-h', '--help'
        cmd_notes_help
        return
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(val, host_ranges))
          return
        end
      end
    end

    if mode == :add
      if host_ranges.compact.empty?
        print_error("Host address or range required")
        return
      end

      if types.nil? || types.size != 1
        print_error("Exactly one type is required")
        return
      end

      if data.nil?
        print_error("Data required")
        return
      end

      type = types.first
      host_ranges.each { |range|
        range.each { |addr|
          note = framework.db.find_or_create_note(host: addr, type: type, data: data)
          break if not note
          print_status("Time: #{note.created_at} Note: host=#{addr} type=#{note.ntype} data=#{note.data}")
        }
      }
      return
    end

    if mode == :update
      if !types.nil? && types.size != 1
        print_error("Exactly one type is required")
        return
      end

      if types.nil? && data.nil?
        print_error("Update requires data or type")
        return
      end
    end

    note_list = []
    if host_ranges.compact.empty?
      # No host specified - collect all notes
      opts = {search_term: search_term}
      opts[:ntype] = types if mode != :update && types && !types.empty?
      note_list = framework.db.notes(opts)
    else
      # Collect notes of specified hosts
      each_host_range_chunk(host_ranges) do |host_search|
        next if host_search && host_search.empty?

        opts = {hosts: {address: host_search}, workspace: framework.db.workspace, search_term: search_term}
        opts[:ntype] = types if mode != :update && types && !types.empty?
        note_list.concat(framework.db.notes(opts))
      end
    end

    # Now display them
    table = Rex::Text::Table.new(
      'Header'  => 'Notes',
      'Indent'  => 1,
      'Columns' => ['Time', 'Host', 'Service', 'Port', 'Protocol', 'Type', 'Data'],
      'SortIndex' => order_by
    )

    matched_note_ids = []
    note_list.each do |note|
      if mode == :update
        begin
          update_opts = {id: note.id}
          unless types.nil?
            note.ntype = types.first
            update_opts[:ntype] = types.first
          end

          unless data.nil?
            note.data = data
            update_opts[:data] = data
          end

          framework.db.update_note(update_opts)
        rescue => e
          elog "There was an error updating note with ID #{note.id}: #{e.message}"
          next
        end
      end

      matched_note_ids << note.id

      row = []
      row << note.created_at

      if note.host
        host = note.host
        row << host.address
        if set_rhosts
          addr = (host.scope.to_s != "" ? host.address + '%' + host.scope : host.address)
          rhosts << addr
        end
      else
        row << ''
      end

      if note.service
        row << note.service.name || ''
        row << note.service.port || ''
        row << note.service.proto || ''
      else
        row << '' # For the Service field
        row << '' # For the Port field
        row << '' # For the Protocol field
      end

      row << note.ntype
      row << note.data.inspect
      table << row
    end

    if mode == :delete
      result = framework.db.delete_note(ids: matched_note_ids)
      delete_count = result.size
    end

    if output_file
      save_csv_notes(output_file, table)
    else
      print_line
      print_line(table.to_s)
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

    print_status("Deleted #{delete_count} notes") if delete_count > 0
  }
  end

  def save_csv_notes(fpath, table)
    begin
      File.open(fpath, 'wb') do |f|
        f.write(table.to_csv)
      end
      print_status("Wrote notes to #{fpath}")
    rescue Errno::EACCES => e
      print_error("Unable to save notes. #{e.message}")
    end
  end

  #
  # Tab completion for the loot command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_loot_tabs(str, words)
    if words.length == 1
      @@loot_opts.option_keys.select { |opt| opt.start_with?(str) }
    end
  end

  def cmd_loot_help
    print_line "Usage: loot [options]"
    print_line " Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]"
    print_line "  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] -t [type]"
    print_line "  Del: loot -d [addr1 addr2 ...]"
    print_line
    print @@loot_opts.usage
    print_line
  end

  @@loot_opts = Rex::Parser::Arguments.new(
    [ '-a', '--add' ] => [ false, 'Add loot to the list of addresses, instead of listing.' ],
    [ '-d', '--delete' ] => [ false, 'Delete *all* loot matching host and type.' ],
    [ '-f', '--file' ] => [ true, 'File with contents of the loot to add.', '<filename>' ],
    [ '-i', '--info' ] => [ true, 'Info of the loot to add.', '<info>' ],
    [ '-t', '--type' ] => [ true, 'Search for a list of types.', '<type1,type2>' ],
    [ '-h', '--help' ] => [ false, 'Show this help information.' ],
    [ '-S', '--search' ] => [ true, 'Search string to filter by.', '<filter>' ],
    [ '-u', '--update' ] => [ false, 'Update loot. Not officially supported.' ]
  )

  def cmd_loot(*args)
    return unless active?

    mode = :search
    host_ranges = []
    types = nil
    delete_count = 0
    search_term = nil
    file = nil
    name = nil
    info = nil
    filename = nil

    @@loot_opts.parse(args) do |opt, idx, val|
      case opt
      when '-a', '--add'
        mode = :add
      when '-d', '--delete'
        mode = :delete
      when '-f', '--file'
        filename = val
        if(!filename)
          print_error("Can't make loot with no filename")
          return
        end
        if (!File.exist?(filename) or !File.readable?(filename))
          print_error("Can't read file")
          return
        end
      when '-i', '--info'
        info = val
        if(!info)
          print_error("Can't make loot with no info")
          return
        end
      when '-t', '--type'
        typelist = val
        if(!typelist)
          print_error("Invalid type list")
          return
        end
        types = typelist.strip().split(",")
      when '-S', '--search'
        search_term = val
      when '-u', '--update' # TODO: This is currently undocumented because it's not officially supported.
        mode = :update
      when '-h', '--help'
        cmd_loot_help
        return
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(val, host_ranges))
          return
        end
      end
    end

    tbl = Rex::Text::Table.new({
        'Header'  => "Loot",
        'Columns' => [ 'host', 'service', 'type', 'name', 'content', 'info', 'path' ],
        # For now, don't perform any word wrapping on the loot table as it breaks the workflow of
        # copying paths and pasting them into applications
        'WordWrap' => false,
      })

    # Sentinel value meaning all
    host_ranges.push(nil) if host_ranges.empty?

    if mode == :add
      if host_ranges.compact.empty?
        print_error('Address list required')
        return
      end
      if info.nil?
        print_error("Info required")
        return
      end
      if filename.nil?
        print_error("Loot file required")
        return
      end
      if types.nil? or types.size != 1
        print_error("Exactly one loot type is required")
        return
      end
      type = types.first
      name = File.basename(filename)
      file = File.open(filename, "rb")
      contents = file.read
      host_ranges.each do |range|
        range.each do |host|
          lootfile = framework.db.find_or_create_loot(:type => type, :host => host, :info => info, :data => contents, :path => filename, :name => name)
          print_status("Added loot for #{host} (#{lootfile})")
        end
      end
      return
    end

    matched_loot_ids = []
    loots = []
    if host_ranges.compact.empty?
      loots = loots + framework.db.loots(workspace: framework.db.workspace, search_term: search_term)
    else
      each_host_range_chunk(host_ranges) do |host_search|
        next if host_search && host_search.empty?

        loots = loots + framework.db.loots(workspace: framework.db.workspace, hosts: { address: host_search }, search_term: search_term)
      end
    end

    loots.each do |loot|
      row = []
      # TODO: This is just a temp implementation of update for the time being since it did not exist before.
      # It should be updated to not pass all of the attributes attached to the object, only the ones being updated.
      if mode == :update
        begin
          loot.info = info if info
          if types && types.size > 1
            print_error "May only pass 1 type when performing an update."
            next
          end
          loot.ltype = types.first if types
          framework.db.update_loot(loot.as_json.symbolize_keys)
        rescue => e
          elog "There was an error updating loot with ID #{loot.id}: #{e.message}"
          next
        end
      end
      row.push (loot.host && loot.host.address) ? loot.host.address : ""
      if (loot.service)
        svc = (loot.service.name ? loot.service.name : "#{loot.service.port}/#{loot.service.proto}")
        row.push svc
      else
        row.push ""
      end
      row.push(loot.ltype)
      row.push(loot.name || "")
      row.push(loot.content_type)
      row.push(loot.info || "")
      row.push(loot.path)

      tbl << row
      matched_loot_ids << loot.id
    end

    if (mode == :delete)
      result = framework.db.delete_loot(ids: matched_loot_ids)
      delete_count = result.size
    end

    print_line
    print_line(tbl.to_s)
    print_status("Deleted #{delete_count} loots") if delete_count > 0
  end

  # :category: Deprecated Commands
  def cmd_db_hosts_help; deprecated_help(:hosts); end
  # :category: Deprecated Commands
  def cmd_db_notes_help; deprecated_help(:notes); end
  # :category: Deprecated Commands
  def cmd_db_vulns_help; deprecated_help(:vulns); end
  # :category: Deprecated Commands
  def cmd_db_services_help; deprecated_help(:services); end
  # :category: Deprecated Commands
  def cmd_db_autopwn_help; deprecated_help; end
  # :category: Deprecated Commands
  def cmd_db_driver_help; deprecated_help; end

  # :category: Deprecated Commands
  def cmd_db_hosts(*args); deprecated_cmd(:hosts, *args); end
  # :category: Deprecated Commands
  def cmd_db_notes(*args); deprecated_cmd(:notes, *args); end
  # :category: Deprecated Commands
  def cmd_db_vulns(*args); deprecated_cmd(:vulns, *args); end
  # :category: Deprecated Commands
  def cmd_db_services(*args); deprecated_cmd(:services, *args); end
  # :category: Deprecated Commands
  def cmd_db_autopwn(*args); deprecated_cmd; end

  #
  # :category: Deprecated Commands
  #
  # This one deserves a little more explanation than standard deprecation
  # warning, so give the user a better understanding of what's going on.
  #
  def cmd_db_driver(*args)
    deprecated_cmd
    print_line
    print_line "Because Metasploit no longer supports databases other than the default"
    print_line "PostgreSQL, there is no longer a need to set the driver. Thus db_driver"
    print_line "is not useful and its functionality has been removed. Usually Metasploit"
    print_line "will already have connected to the database; check db_status to see."
    print_line
    cmd_db_status
  end

  def cmd_db_import_tabs(str, words)
    tab_complete_filenames(str, words)
  end

  def cmd_db_import_help
    print_line "Usage: db_import <filename> [file2...]"
    print_line
    print_line "Filenames can be globs like *.xml, or **/*.xml which will search recursively"
    print_line "Currently supported file types include:"
    print_line "    Acunetix"
    print_line "    Amap Log"
    print_line "    Amap Log -m"
    print_line "    Appscan"
    print_line "    Burp Session XML"
    print_line "    Burp Issue XML"
    print_line "    CI"
    print_line "    Foundstone"
    print_line "    FusionVM XML"
    print_line "    Group Policy Preferences Credentials"
    print_line "    IP Address List"
    print_line "    IP360 ASPL"
    print_line "    IP360 XML v3"
    print_line "    Libpcap Packet Capture"
    print_line "    Masscan XML"
    print_line "    Metasploit PWDump Export"
    print_line "    Metasploit XML"
    print_line "    Metasploit Zip Export"
    print_line "    Microsoft Baseline Security Analyzer"
    print_line "    NeXpose Simple XML"
    print_line "    NeXpose XML Report"
    print_line "    Nessus NBE Report"
    print_line "    Nessus XML (v1)"
    print_line "    Nessus XML (v2)"
    print_line "    NetSparker XML"
    print_line "    Nikto XML"
    print_line "    Nmap XML"
    print_line "    OpenVAS Report"
    print_line "    OpenVAS XML (optional arguments -cert -dfn)"
    print_line "    Outpost24 XML"
    print_line "    Qualys Asset XML"
    print_line "    Qualys Scan XML"
    print_line "    Retina XML"
    print_line "    Spiceworks CSV Export"
    print_line "    Wapiti XML"
    print_line
  end

  #
  # Generic import that automatically detects the file type
  #
  def cmd_db_import(*args)
    return unless active?
    openvas_cert = false
    openvas_dfn = false
  ::ApplicationRecord.connection_pool.with_connection {
    if args.include?("-h") || ! (args && args.length > 0)
      cmd_db_import_help
      return
    end
    if args.include?("-dfn")
      openvas_dfn = true
    end
    if args.include?("-cert")
      openvas_cert = true
    end
    options = {:openvas_dfn => openvas_dfn, :openvas_cert => openvas_cert}
    args.each { |glob|
      next if (glob.include?("-cert") || glob.include?("-dfn"))
      files = ::Dir.glob(::File.expand_path(glob))
      if files.empty?
        print_error("No such file #{glob}")
        next
      end
      files.each { |filename|
        if (not ::File.readable?(filename))
          print_error("Could not read file #{filename}")
          next
        end
        begin
          warnings = 0
          framework.db.import_file(:filename => filename, :options => options) do |type,data|
            case type
            when :debug
              print_error("DEBUG: #{data.inspect}")
            when :vuln
              inst = data[1] == 1 ? "instance" : "instances"
              print_status("Importing vulnerability '#{data[0]}' (#{data[1]} #{inst})")
            when :filetype
              print_status("Importing '#{data}' data")
            when :parser
              print_status("Import: Parsing with '#{data}'")
            when :address
              print_status("Importing host #{data}")
            when :service
              print_status("Importing service #{data}")
            when :msf_loot
              print_status("Importing loot #{data}")
            when :msf_task
              print_status("Importing task #{data}")
            when :msf_report
              print_status("Importing report #{data}")
            when :pcap_count
              print_status("Import: #{data} packets processed")
            when :record_count
              print_status("Import: #{data[1]} records processed")
            when :warning
              print_error
              data.split("\n").each do |line|
                print_error(line)
              end
              print_error
              warnings += 1
            end
          end
          print_status("Successfully imported #{filename}")

          print_error("Please note that there were #{warnings} warnings") if warnings > 1
          print_error("Please note that there was one warning") if warnings == 1

        rescue Msf::DBImportError => e
          print_error("Failed to import #{filename}: #{$!}")
          elog("Failed to import #{filename}", error: e)
          dlog("Call stack: #{$@.join("\n")}", LEV_3)
          next
        rescue REXML::ParseException => e
          print_error("Failed to import #{filename} due to malformed XML:")
          print_error("#{e.class}: #{e}")
          elog("Failed to import #{filename}", error: e)
          dlog("Call stack: #{$@.join("\n")}", LEV_3)
          next
        end
      }
    }
  }
  end

  def cmd_db_export_help
    # Like db_hosts and db_services, this creates a list of columns, so
    # use its -h
    cmd_db_export("-h")
  end

  #
  # Export an XML
  #
  def cmd_db_export(*args)
    return unless active?
  ::ApplicationRecord.connection_pool.with_connection {

    export_formats = %W{xml pwdump}
    format = 'xml'
    output = nil

    while (arg = args.shift)
      case arg
      when '-h','--help'
        print_line "Usage:"
        print_line "    db_export -f <format> [filename]"
        print_line "    Format can be one of: #{export_formats.join(", ")}"
      when '-f','--format'
        format = args.shift.to_s.downcase
      else
        output = arg
      end
    end

    if not output
      print_error("No output file was specified")
      return
    end

    if not export_formats.include?(format)
      print_error("Unsupported file format: #{format}")
      print_error("Unsupported file format: '#{format}'. Must be one of: #{export_formats.join(", ")}")
      return
    end

    print_status("Starting export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
    framework.db.run_db_export(output, format)
    print_status("Finished export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
  }
  end

  def find_nmap_path
    Rex::FileUtils.find_full_path("nmap") || Rex::FileUtils.find_full_path("nmap.exe")
  end

  #
  # Import Nmap data from a file
  #
  def cmd_db_nmap(*args)
    return unless active?
  ::ApplicationRecord.connection_pool.with_connection {
    if (args.length == 0)
      print_status("Usage: db_nmap [--save | [--help | -h]] [nmap options]")
      return
    end

    save = false
    arguments = []
    while (arg = args.shift)
      case arg
      when '--save'
        save = true
      when '--help', '-h'
        cmd_db_nmap_help
        return
      else
        arguments << arg
      end
    end

    nmap = find_nmap_path
    unless nmap
      print_error("The nmap executable could not be found")
      return
    end

    fd = Rex::Quickfile.new(['msf-db-nmap-', '.xml'], Msf::Config.local_directory)

    begin
      # When executing native Nmap in Cygwin, expand the Cygwin path to a Win32 path
      if(Rex::Compat.is_cygwin and nmap =~ /cygdrive/)
        # Custom function needed because cygpath breaks on 8.3 dirs
        tout = Rex::Compat.cygwin_to_win32(fd.path)
        arguments.push('-oX', tout)
      else
        arguments.push('-oX', fd.path)
      end

      run_nmap(nmap, arguments)

      framework.db.import_nmap_xml_file(:filename => fd.path)

      print_status("Saved NMAP XML results to #{fd.path}") if save
    ensure
      fd.close
      fd.unlink unless save
    end
  }
  end

  def cmd_db_nmap_help
    nmap = find_nmap_path
    unless nmap
      print_error("The nmap executable could not be found")
      return
    end

    stdout, stderr = Open3.capture3([nmap, 'nmap'], '--help')

    stdout.each_line do |out_line|
      next if out_line.strip.empty?
      print_status(out_line.strip)
    end

    stderr.each_line do |err_line|
      next if err_line.strip.empty?
      print_error(err_line.strip)
    end
  end

  def cmd_db_nmap_tabs(str, words)
    nmap = find_nmap_path
    unless nmap
      return
    end

    stdout, stderr = Open3.capture3([nmap, 'nmap'], '--help')
    tabs = []
    stdout.each_line do |out_line|
      if out_line.strip.starts_with?('-')
        tabs.push(out_line.strip.split(':').first)
      end
    end

    stderr.each_line do |err_line|
      next if err_line.strip.empty?
      print_error(err_line.strip)
    end

    return tabs
  end

  #
  # Database management
  #
  def db_check_driver
    unless framework.db.driver
      print_error("No database driver installed.")
      return false
    end
    true
  end

  #
  # Is everything working?
  #
  def cmd_db_status(*args)
    return if not db_check_driver

    if framework.db.connection_established?
      print_connection_info
    else
      print_status("#{framework.db.driver} selected, no connection")
    end
  end


  def cmd_db_connect_help
    print_line("   USAGE:")
    print_line("      * Postgres Data Service:")
    print_line("          db_connect <user:[pass]>@<host:[port]>/<database>")
    print_line("        Examples:")
    print_line("          db_connect user@metasploit3")
    print_line("          db_connect user:pass@192.168.0.2/metasploit3")
    print_line("          db_connect user:pass@192.168.0.2:1500/metasploit3")
    print_line("          db_connect -y [path/to/database.yml]")
    print_line(" ")
    print_line("      * HTTP Data Service:")
    print_line("          db_connect [options] <http|https>://<host:[port]>")
    print_line("        Examples:")
    print_line("          db_connect http://localhost:8080")
    print_line("          db_connect http://my-super-msf-data.service.com")
    print_line("          db_connect -c ~/cert.pem -t 6a7a74c1a5003802c955ead1bbddd4ab1b05a7f2940b4732d34bfc555bc6e1c5d7611a497b29e8f0 https://localhost:8080")
    print_line("        NOTE: You must be connected to a Postgres data service in order to successfully connect to a HTTP data service.")
    print_line(" ")
    print_line("      Persisting Connections:")
    print_line("        db_connect --name <name to save connection as> [options] <address>")
    print_line("      Examples:")
    print_line("        Saving:     db_connect --name LA-server http://123.123.123.45:1234")
    print_line("        Connecting: db_connect LA-server")
    print_line(" ")
    print_line("   OPTIONS:")
    print_line("       -l,--list-services List the available data services that have been previously saved.")
    print_line("       -y,--yaml          Connect to the data service specified in the provided database.yml file.")
    print_line("       -n,--name          Name used to store the connection. Providing an existing name will overwrite the settings for that connection.")
    print_line("       -c,--cert          Certificate file matching the remote data server's certificate. Needed when using self-signed SSL cert.")
    print_line("       -t,--token         The API token used to authenticate to the remote data service.")
    print_line("       --skip-verify      Skip validating authenticity of server's certificate (NOT RECOMMENDED).")
    print_line("")
  end

  def cmd_db_connect(*args)
    return if not db_check_driver

    opts = {}
    while (arg = args.shift)
      case arg
      when '-h', '--help'
        cmd_db_connect_help
        return
      when '-y', '--yaml'
        opts[:yaml_file] = args.shift
      when '-c', '--cert'
        opts[:cert] = args.shift
      when '-t', '--token'
        opts[:api_token] = args.shift
      when '-l', '--list-services'
        list_saved_data_services
        return
      when '-n', '--name'
        opts[:name] = args.shift
        if opts[:name] =~ /\/|\[|\]/
          print_error "Provided name contains an invalid character. Aborting connection."
          return
        end
      when '--skip-verify'
        opts[:skip_verify] = true
      else
        found_name = ::Msf::DbConnector.data_service_search(name: arg)
        if found_name
          opts = ::Msf::DbConnector.load_db_config(found_name)
        else
          opts[:url] = arg
        end
      end
    end

    if !opts[:url] && !opts[:yaml_file]
      print_error 'A URL or saved data service name is required.'
      print_line
      cmd_db_connect_help
      return
    end

    if opts[:url] =~ /http/
      new_conn_type = 'http'
    else
      new_conn_type = framework.db.driver
    end

    # Currently only able to be connected to one DB at a time
    if framework.db.connection_established?
      # But the http connection still requires a local database to support AR, so we have to allow that
      # Don't allow more than one HTTP service, though
      if new_conn_type != 'http' || framework.db.get_services_metadata.count >= 2
        print_error('Connection already established. Only one connection is allowed at a time.')
        print_error('Run db_disconnect first if you wish to connect to a different data service.')
        print_line
        print_line 'Current connection information:'
        print_connection_info
        return
      end
    end

    result = Msf::DbConnector.db_connect(framework, opts)
    if result[:error]
      print_error result[:error]
      return
    end

    if result[:result]
      print_status result[:result]
    end
    if framework.db.active
      name = opts[:name]
      if !name || name.empty?
        if found_name
          name = found_name
        elsif result[:data_service_name]
          name = result[:data_service_name]
        else
          name = Rex::Text.rand_text_alphanumeric(8)
        end
      end

      save_db_to_config(framework.db, name)
      @current_data_service = name
    end
  end

  def cmd_db_disconnect_help
    print_line "Usage:"
    print_line "    db_disconnect              Temporarily disconnects from the currently configured dataservice."
    print_line "    db_disconnect --clear      Clears the default dataservice that msfconsole will use when opened."
    print_line
  end

  def cmd_db_disconnect(*args)
    return if not db_check_driver

    if args[0] == '-h' || args[0] == '--help'
      cmd_db_disconnect_help
      return
    elsif args[0] == '-c' || args[0] == '--clear'
      clear_default_db
      return
    end

    previous_name = framework.db.name
    result = Msf::DbConnector.db_disconnect(framework)

    if result[:error]
      print_error "Unable to disconnect from the data service: #{@current_data_service}"
      print_error result[:error]
    elsif result[:old_data_service_name].nil?
      print_error 'Not currently connected to a data service.'
    else
      print_line "Successfully disconnected from the data service: #{previous_name}."
      @current_data_service = result[:data_service_name]
      if @current_data_service
        print_line "Now connected to: #{@current_data_service}."
      end
    end
  end

  def cmd_db_rebuild_cache(*args)
    print_line "This command is deprecated with Metasploit 5"
  end

  def cmd_db_save_help
    print_line "Usage: db_save"
    print_line
    print_line "Save the current data service connection as the default to reconnect on startup."
    print_line
  end

  def cmd_db_save(*args)
    while (arg = args.shift)
      case arg
        when '-h', '--help'
          cmd_db_save_help
          return
      end
    end

    if !framework.db.active || !@current_data_service
      print_error "Not currently connected to a data service that can be saved."
      return
    end

    begin
      Msf::Config.save(DB_CONFIG_PATH => { 'default_db' => @current_data_service })
      print_line "Successfully saved data service as default: #{@current_data_service}"
    rescue ArgumentError => e
      print_error e.message
    end
  end

  def save_db_to_config(database, database_name)
    if database_name =~ /\/|\[|\]/
      raise ArgumentError, 'Data service name contains an invalid character.'
    end
    config_path = "#{DB_CONFIG_PATH}/#{database_name}"
    config_opts = {}
    if !database.is_local?
      begin
        config_opts['url'] = database.endpoint
        if database.https_opts
          config_opts['cert'] = database.https_opts[:cert] if database.https_opts[:cert]
          config_opts['skip_verify'] = true if database.https_opts[:skip_verify]
        end
        if database.api_token
          config_opts['api_token'] = database.api_token
        end
        Msf::Config.save(config_path => config_opts)
      rescue => e
        print_error "There was an error saving the data service configuration: #{e.message}"
      end
    else
      url = Msf::DbConnector.build_postgres_url
      config_opts['url'] = url
      Msf::Config.save(config_path => config_opts)
    end
  end

  def cmd_db_remove_help
    print_line "Usage: db_remove <name>"
    print_line
    print_line "Delete the specified saved data service."
    print_line
  end

  def cmd_db_remove(*args)
    if args[0] == '-h' || args[0] == '--help' || args[0].nil? || args[0].empty?
      cmd_db_remove_help
      return
    end
    delete_db_from_config(args[0])
  end

  def delete_db_from_config(db_name)
    conf = Msf::Config.load
    db_path = "#{DB_CONFIG_PATH}/#{db_name}"
    if conf[db_path]
      clear_default_db if conf[DB_CONFIG_PATH]['default_db'] && conf[DB_CONFIG_PATH]['default_db'] == db_name
      Msf::Config.delete_group(db_path)
      print_line "Successfully deleted data service: #{db_name}"
    else
      print_line "Unable to locate saved data service with name #{db_name}."
    end
  end

  def clear_default_db
    conf = Msf::Config.load
    if conf[DB_CONFIG_PATH] && conf[DB_CONFIG_PATH]['default_db']
      updated_opts = conf[DB_CONFIG_PATH]
      updated_opts.delete('default_db')
      Msf::Config.save(DB_CONFIG_PATH => updated_opts)
      print_line "Cleared the default data service."
    else
      print_line "No default data service was configured."
    end
  end

  def db_find_tools(tools)
    missed  = []
    tools.each do |name|
      if(! Rex::FileUtils.find_full_path(name))
        missed << name
      end
    end
    if(not missed.empty?)
      print_error("This database command requires the following tools to be installed: #{missed.join(", ")}")
      return
    end
    true
  end

  #######
  private

  def run_nmap(nmap, arguments, use_sudo: false)
    print_warning('Running Nmap with sudo') if use_sudo
    begin
      nmap_pipe = use_sudo ? ::Open3::popen3('sudo', nmap, *arguments) : ::Open3::popen3(nmap, *arguments)
      temp_nmap_threads = []
      temp_nmap_threads << framework.threads.spawn("db_nmap-Stdout", false, nmap_pipe[1]) do |np_1|
        np_1.each_line do |nmap_out|
          next if nmap_out.strip.empty?
          print_status("Nmap: #{nmap_out.strip}")
        end
      end

      temp_nmap_threads << framework.threads.spawn("db_nmap-Stderr", false, nmap_pipe[2]) do |np_2|

        np_2.each_line do |nmap_err|
          next if nmap_err.strip.empty?
          print_status("Nmap: '#{nmap_err.strip}'")
          # Check if the stderr text includes 'root', this only happens if the scan requires root privileges
          if nmap_err =~ /requires? root privileges/ or
            nmap_err.include? 'only works if you are root' or nmap_err =~ /requires? raw socket access/
            return run_nmap(nmap, arguments, use_sudo: true) unless use_sudo
          end
        end
      end

      temp_nmap_threads.map { |t| t.join rescue nil }
      nmap_pipe.each { |p| p.close rescue nil }
    rescue ::IOError
    end
  end

  #######

  def print_connection_info
    cdb = ''
    if framework.db.driver == 'http'
      cdb = framework.db.name
    else
      ::ApplicationRecord.connection_pool.with_connection do |conn|
        if conn.respond_to?(:current_database)
          cdb = conn.current_database
        end
      end
    end
    output = "Connected to #{cdb}. Connection type: #{framework.db.driver}."
    output += " Connection name: #{@current_data_service}." if @current_data_service
    print_status(output)
  end

  def list_saved_data_services
    conf = Msf::Config.load
    default = nil
    tbl = Rex::Text::Table.new({
                                   'Header'    => 'Data Services',
                                   'Columns'   => ['current', 'name', 'url', 'default?'],
                                   'SortIndex' => 1
                               })

    conf.each_pair do |k,v|
      if k =~ /#{DB_CONFIG_PATH}/
        default = v['default_db'] if v['default_db']
        name = k.split('/').last
        next if name == 'database' # Data service information is not stored in 'framework/database', just metadata
        url = v['url']
        current = ''
        current = '*' if name == @current_data_service
        default_output = ''
        default_output = '*' if name == default
        line = [current, name, url, default_output]
        tbl << line
      end
    end
    print_line
    print_line tbl.to_s
  end

  def print_msgs(status_msg, error_msg)
    status_msg.each do |s|
      print_status(s)
    end

    error_msg.each do |e|
      print_error(e)
    end
  end

  def _format_vulns_and_vuln_attempts(vulns)
    vulns.map.with_index do |vuln, index|
      vuln_formatted = <<~EOF.strip.indent(2)
        #{index}. Vuln ID: #{vuln.id}
           Timestamp: #{vuln.created_at}
           Host: #{vuln.host.address}
           Name: #{vuln.name}
           References: #{vuln.refs.map {|r| r.name}.join(',')}
           Information: #{_format_vuln_value(vuln.info)}
      EOF

      vuln_attempts_formatted = vuln.vuln_attempts.map.with_index do |vuln_attempt, i|
        <<~EOF.strip.indent(5)
          #{i}. ID: #{vuln_attempt.id}
             Vuln ID: #{vuln_attempt.vuln_id}
             Timestamp: #{vuln_attempt.attempted_at}
             Exploit: #{vuln_attempt.exploited}
             Fail reason: #{_format_vuln_value(vuln_attempt.fail_reason)}
             Username: #{vuln_attempt.username}
             Module: #{vuln_attempt.module}
             Session ID: #{_format_vuln_value(vuln_attempt.session_id)}
             Loot ID: #{_format_vuln_value(vuln_attempt.loot_id)}
             Fail Detail: #{_format_vuln_value(vuln_attempt.fail_detail)}
        EOF
      end

      { :vuln => vuln_formatted, :vuln_attempts => vuln_attempts_formatted }
    end
  end

  def _print_vulns_and_attempts(vulns_and_attempts)
    print_line("Vulnerabilities\n===============")
    vulns_and_attempts.each do |vuln_and_attempt|
      print_line(vuln_and_attempt[:vuln])
      print_line("Vuln attempts:".indent(5))
      vuln_and_attempt[:vuln_attempts].each do |attempt|
        print_line(attempt)
      end
    end
  end

  def _format_vuln_value(s)
    s.blank? ? s.inspect  : s.to_s
  end
end

end end end end
