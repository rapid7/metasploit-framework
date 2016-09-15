# -*- coding: binary -*-

require 'rexml/document'
require 'rex/parser/nmap_xml'
require 'msf/core/db_export'

module Msf
module Ui
module Console
module CommandDispatcher

class Db

  require 'tempfile'

  include Msf::Ui::Console::CommandDispatcher
  include Metasploit::Credential::Creation

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
      "db_connect"    => "Connect to an existing database",
      "db_disconnect" => "Disconnect from the current database instance",
      "db_status"     => "Show the current database status",
    }

    more = {
      "workspace"     => "Switch between database workspaces",
      "hosts"         => "List all hosts in the database",
      "services"      => "List all services in the database",
      "vulns"         => "List all vulnerabilities in the database",
      "notes"         => "List all notes in the database",
      "loot"          => "List all loot in the database",
      "creds"         => "List all credentials in the database",
      "db_import"     => "Import a scan result file (filetype will be auto-detected)",
      "db_export"     => "Export a file containing the contents of the database",
      "db_nmap"       => "Executes nmap and records the output automatically",
      "db_rebuild_cache" => "Rebuilds the database-stored module cache"
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

  def allowed_cred_types
    %w(password ntlm hash)
  end

  #
  # Returns true if the db is connected, prints an error and returns
  # false if not.
  #
  # All commands that require an active database should call this before
  # doing anything.
  #
  def active?
    if not framework.db.active
      print_error("Database not connected")
      return false
    end
    true
  end

  def cmd_workspace_help
    print_line "Usage:"
    print_line "    workspace                  List workspaces"
    print_line "    workspace [name]           Switch workspace"
    print_line "    workspace -a [name] ...    Add workspace(s)"
    print_line "    workspace -d [name] ...    Delete workspace(s)"
    print_line "    workspace -D               Delete all workspaces"
    print_line "    workspace -r <old> <new>   Rename workspace"
    print_line "    workspace -h               Show this help information"
    print_line
  end

  def cmd_workspace(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    while (arg = args.shift)
      case arg
      when '-h','--help'
        cmd_workspace_help
        return
      when '-a','--add'
        adding = true
      when '-d','--del'
        deleting = true
      when '-D','--delete-all'
        delete_all = true
      when '-r','--rename'
        renaming = true
      else
        names ||= []
        names << arg
      end
    end

    if adding and names
      # Add workspaces
      workspace = nil
      names.each do |name|
        workspace = framework.db.add_workspace(name)
        print_status("Added workspace: #{workspace.name}")
      end
      framework.db.workspace = workspace
    elsif deleting and names
      delete_workspaces(names)
    elsif delete_all
      delete_workspaces(framework.db.workspaces.map(&:name))
    elsif renaming
      if names.length != 2
        print_error("Wrong number of arguments to rename")
        return
      end
      old, new = names

      workspace = framework.db.find_workspace(old)

      old_is_active = (framework.db.workspace == workspace)
      recreate_default = workspace.default?

      if workspace.nil?
        print_error("Workspace not found: #{name}")
        return
      end

      if framework.db.find_workspace(new)
        print_error("Workspace exists: #{new}")
        return
      end

      workspace.name = new
      workspace.save!

      # Recreate the default workspace to avoid errors
      if recreate_default
        framework.db.add_workspace(old)
        print_status("Recreated default workspace after rename")
      end

      # Switch to new workspace if old name was active
      if old_is_active
        framework.db.workspace = workspace
        print_status("Switched workspace: #{framework.db.workspace.name}")
      end
    elsif names
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
      # List workspaces
      framework.db.workspaces.each do |s|
        pad = (s.name == framework.db.workspace.name) ? "* " : "  "
        print_line("#{pad}#{s.name}")
      end
    end
  }
  end

  def delete_workspaces(names)
    switched = false
    # Delete workspaces
    names.each do |name|
      workspace = framework.db.find_workspace(name)
      if workspace.nil?
        print_error("Workspace not found: #{name}")
      elsif workspace.default?
        workspace.destroy
        workspace = framework.db.add_workspace(name)
        print_status("Deleted and recreated the default workspace")
      else
        # switch to the default workspace if we're about to delete the current one
        if framework.db.workspace.name == workspace.name
          framework.db.workspace = framework.db.default_workspace
          switched = true
        end
        # now destroy the named workspace
        workspace.destroy
        print_status("Deleted workspace: #{name}")
      end
    end
    print_status("Switched workspace: #{framework.db.workspace.name}") if switched
  end

  def cmd_workspace_tabs(str, words)
    return [] unless active?
    framework.db.workspaces.map { |s| s.name } if (words & ['-a','--add']).empty?
  end

  def cmd_hosts_help
    # This command does some lookups for the list of appropriate column
    # names, so instead of putting all the usage stuff here like other
    # help methods, just use it's "-h" so we don't have to recreating
    # that list
    cmd_hosts("-h")
  end

  def change_host_info(rws, data)
    if rws == [nil]
      print_error("In order to change the host info, you must provide a range of hosts")
      return
    end

    rws.each do |rw|
      rw.each do |ip|
        id = framework.db.get_host(:address => ip).id
        framework.db.hosts.update(id, :info => data)
        framework.db.report_note(:host => ip, :type => 'host.info', :data => data)
      end
    end
  end

  def change_host_name(rws, data)
    if rws == [nil]
      print_error("In order to change the host name, you must provide a range of hosts")
      return
    end

    rws.each do |rw|
      rw.each do |ip|
        id = framework.db.get_host(:address => ip).id
        framework.db.hosts.update(id, :name => data)
        framework.db.report_note(:host => ip, :type => 'host.name', :data => data)
      end
    end
  end

  def change_host_comment(rws, data)
    if rws == [nil]
      print_error("In order to change the comment, you must provide a range of hosts")
      return
    end

    rws.each do |rw|
      rw.each do |ip|
        id = framework.db.get_host(:address => ip).id
        framework.db.hosts.update(id, :comments => data)
        framework.db.report_note(:host => ip, :type => 'host.comments', :data => data)
      end
    end
  end

  def add_host_tag(rws, tag_name)
    if rws == [nil]
      print_error("In order to add a tag, you must provide a range of hosts")
      return
    end

    rws.each do |rw|
      rw.each do |ip|
        wspace = framework.db.workspace
        host = framework.db.get_host(:workspace => wspace, :address => ip)
        if host
          possible_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and hosts.address = ? and tags.name = ?", wspace.id, ip, tag_name).order("tags.id DESC").limit(1)
          tag = (possible_tags.blank? ? Mdm::Tag.new : possible_tags.first)
          tag.name = tag_name
          tag.hosts = [host]
          tag.save! if tag.changed?
        end
      end
    end
  end

  def delete_host_tag(rws, tag_name)
    wspace = framework.db.workspace
    tag_ids = []
    if rws == [nil]
      found_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and tags.name = ?", wspace.id, tag_name)
      found_tags.each do |t|
        tag_ids << t.id
      end
    else
      rws.each do |rw|
        rw.each do |ip|
          found_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and hosts.address = ? and tags.name = ?", wspace.id, ip, tag_name)
            found_tags.each do |t|
            tag_ids << t.id
          end
        end
      end
    end

    tag_ids.each do |id|
      tag = Mdm::Tag.find_by_id(id)
      tag.hosts.delete
      tag.destroy
    end
  end

  def cmd_hosts(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    onlyup = false
    set_rhosts = false
    mode = []
    delete_count = 0

    rhosts = []
    host_ranges = []
    search_term = nil

    output = nil
    default_columns = ::Mdm::Host.column_names.sort
    default_columns << 'tags' # Special case
    virtual_columns = [ 'svcs', 'vulns', 'workspace', 'tags' ]

    col_search = [ 'address', 'mac', 'name', 'os_name', 'os_flavor', 'os_sp', 'purpose', 'info', 'comments']

    default_columns.delete_if {|v| (v[-2,2] == "id")}
    while (arg = args.shift)
      case arg
      when '-a','--add'
        mode << :add
      when '-d','--delete'
        mode << :delete
      when '-c'
        list = args.shift
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
      when '-u','--up'
        onlyup = true
      when '-o'
        output = args.shift
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = /#{args.shift}/nmi
      when '-i', '--info'
        mode << :new_info
        info_data = args.shift
      when '-n', '--name'
        mode << :new_name
        name_data = args.shift
      when '-m', '--comment'
        mode << :new_comment
        comment_data = args.shift
      when '-t', '--tag'
        mode << :tag
        tag_name = args.shift
      when '-h','--help'
        print_line "Usage: hosts [ options ] [addr1 addr2 ...]"
        print_line
        print_line "OPTIONS:"
        print_line "  -a,--add          Add the hosts instead of searching"
        print_line "  -d,--delete       Delete the hosts instead of searching"
        print_line "  -c <col1,col2>    Only show the given columns (see list below)"
        print_line "  -h,--help         Show this help information"
        print_line "  -u,--up           Only show hosts which are up"
        print_line "  -o <file>         Send output to a file in csv format"
        print_line "  -R,--rhosts       Set RHOSTS from the results of the search"
        print_line "  -S,--search       Search string to filter by"
        print_line "  -i,--info         Change the info of a host"
        print_line "  -n,--name         Change the name of a host"
        print_line "  -m,--comment      Change the comment of a host"
        print_line "  -t,--tag          Add or specify a tag to a range of hosts"
        print_line
        print_line "Available columns: #{default_columns.join(", ")}"
        print_line
        return
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
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

    # If we got here, we're searching.  Delete implies search
    tbl = Rex::Text::Table.new(
      {
        'Header'  => "Hosts",
        'Columns' => col_names,
      })

    # Sentinal value meaning all
    host_ranges.push(nil) if host_ranges.empty?

    case
    when mode == [:new_info]
      change_host_info(host_ranges, info_data)
      return
    when mode == [:new_name]
      change_host_name(host_ranges, name_data)
      return
    when mode == [:new_comment]
      change_host_comment(host_ranges, comment_data)
      return
    when mode == [:tag]
      begin
        add_host_tag(host_ranges, tag_name)
      rescue ::Exception => e
        if e.message.include?('Validation failed')
          print_error(e.message)
        else
          raise e
        end
      end
      return
    when mode.include?(:tag) && mode.include?(:delete)
      delete_host_tag(host_ranges, tag_name)
      return
    end

    each_host_range_chunk(host_ranges) do |host_search|
      framework.db.hosts(framework.db.workspace, onlyup, host_search).each do |host|
        if search_term
          next unless (
            host.attribute_names.any? { |a| host[a.intern].to_s.match(search_term) } ||
            !Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and hosts.address = ? and tags.name = ?", framework.db.workspace.id, host.address, search_term.source).references(:hosts).order("tags.id DESC").empty?
          )
        end

        columns = col_names.map do |n|
          # Deal with the special cases
          if virtual_columns.include?(n)
            case n
            when "svcs";      host.services.length
            when "vulns";     host.vulns.length
            when "workspace"; host.workspace.name
            when "tags"
              found_tags = Mdm::Tag.joins(:hosts).where("hosts.workspace_id = ? and hosts.address = ?", framework.db.workspace.id, host.address).order("tags.id DESC")
              tag_names = []
              found_tags.each { |t| tag_names << t.name }
              found_tags * ", "
            end
          # Otherwise, it's just an attribute
          else
            host.attributes[n] || ""
          end
        end

        tbl << columns
        if set_rhosts
          addr = (host.scope ? host.address + '%' + host.scope : host.address)
          rhosts << addr
        end
        if mode == [:delete]
          host.destroy
          delete_count += 1
        end
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
  }
  end

  def cmd_services_help
    # Like cmd_hosts, use "-h" instead of recreating the column list
    # here
    cmd_services("-h")
  end

  def cmd_services(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    mode = :search
    onlyup = false
    output_file = nil
    set_rhosts = false
    col_search = ['port', 'proto', 'name', 'state', 'info']
    default_columns = ::Mdm::Service.column_names.sort
    default_columns.delete_if {|v| (v[-2,2] == "id")}

    host_ranges  = []
    port_ranges  = []
    rhosts       = []
    delete_count = 0
    search_term  = nil

    # option parsing
    while (arg = args.shift)
      case arg
      when '-a','--add'
        mode = :add
      when '-d','--delete'
        mode = :delete
      when '-u','--up'
        onlyup = true
      when '-c'
        list = args.shift
        if(!list)
          print_error("Invalid column list")
          return
        end
        col_search = list.strip().split(",")
        col_search.each { |c|
          if not default_columns.include? c
            print_error("Invalid column list. Possible values are (#{default_columns.join("|")})")
            return
          end
        }
      when '-p'
        unless (arg_port_range(args.shift, port_ranges, true))
          return
        end
      when '-r'
        proto = args.shift
        if (!proto)
          print_status("Invalid protocol")
          return
        end
        proto = proto.strip
      when '-s'
        namelist = args.shift
        if (!namelist)
          print_error("Invalid name list")
          return
        end
        names = namelist.strip().split(",")
      when '-o'
        output_file = args.shift
        if (!output_file)
          print_error("Invalid output filename")
          return
        end
        output_file = ::File.expand_path(output_file)
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = /#{args.shift}/nmi

      when '-h','--help'
        print_line
        print_line "Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]"
        print_line
        print_line "  -a,--add          Add the services instead of searching"
        print_line "  -d,--delete       Delete the services instead of searching"
        print_line "  -c <col1,col2>    Only show the given columns"
        print_line "  -h,--help         Show this help information"
        print_line "  -s <name1,name2>  Search for a list of service names"
        print_line "  -p <port1,port2>  Search for a list of ports"
        print_line "  -r <protocol>     Only show [tcp|udp] services"
        print_line "  -u,--up           Only show services which are up"
        print_line "  -o <file>         Send output to a file in csv format"
        print_line "  -R,--rhosts       Set RHOSTS from the results of the search"
        print_line "  -S,--search       Search string to filter by"
        print_line
        print_line "Available columns: #{default_columns.join(", ")}"
        print_line
        return
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
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
      host_ranges.each do |range|
        range.each do |addr|
          host = framework.db.find_or_create_host(:host => addr)
          next if not host
          info = {
            :host => host,
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
    col_names = default_columns
    if col_search
      col_names = col_search
    end
    tbl = Rex::Text::Table.new({
        'Header'  => "Services",
        'Columns' => ['host'] + col_names,
      })

    # Sentinal value meaning all
    host_ranges.push(nil) if host_ranges.empty?
    ports = nil if ports.empty?

    each_host_range_chunk(host_ranges) do |host_search|
      framework.db.services(framework.db.workspace, onlyup, proto, host_search, ports, names).each do |service|

        host = service.host
        if search_term
          next unless(
            host.attribute_names.any? { |a| host[a.intern].to_s.match(search_term)} or
            service.attribute_names.any? { |a| service[a.intern].to_s.match(search_term)}
          )
        end

        columns = [host.address] + col_names.map { |n| service[n].to_s || "" }
        tbl << columns
        if set_rhosts
          addr = (host.scope ? host.address + '%' + host.scope : host.address )
          rhosts << addr
        end

        if (mode == :delete)
          service.destroy
          delete_count += 1
        end
      end
    end

    print_line
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

  }
  end

  def cmd_vulns_help
    print_line "Print all vulnerabilities in the database"
    print_line
    print_line "Usage: vulns [addr range]"
    print_line
    print_line "  -h,--help             Show this help information"
    print_line "  -p,--port <portspec>  List vulns matching this port spec"
    print_line "  -s <svc names>        List vulns matching these service names"
    print_line "  -R,--rhosts           Set RHOSTS from the results of the search"
    print_line "  -S,--search           Search string to filter by"
    print_line "  -i,--info             Display Vuln Info"
    print_line
    print_line "Examples:"
    print_line "  vulns -p 1-65536          # only vulns with associated services"
    print_line "  vulns -p 1-65536 -s http  # identified as http on any port"
    print_line
  end

  def cmd_vulns(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {

    host_ranges = []
    port_ranges = []
    svcs        = []
    rhosts    	= []

    search_term = nil
    show_info   = false
    set_rhosts  = false

    # Short-circuit help
    if args.delete "-h"
      cmd_vulns_help
      return
    end

    while (arg = args.shift)
      case arg
      #when "-a","--add"
      #	mode = :add
      #when "-d"
      #	mode = :delete
      when "-h","--help"
        cmd_vulns_help
        return
      when "-p","--port"
        unless (arg_port_range(args.shift, port_ranges, true))
          return
        end
      when "-s","--service"
        service = args.shift
        if (!service)
          print_error("Argument required for -s")
          return
        end
        svcs = service.split(/[\s]*,[\s]*/)
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = /#{args.shift}/nmi
      when '-i', '--info'
        show_info = true
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
          return
        end
      end
    end

    # normalize
    host_ranges.push(nil) if host_ranges.empty?
    ports = port_ranges.flatten.uniq
    svcs.flatten!

    each_host_range_chunk(host_ranges) do |host_search|
      framework.db.hosts(framework.db.workspace, false, host_search).each do |host|
        host.vulns.each do |vuln|
          if search_term
            next unless(
              vuln.host.attribute_names.any? { |a| vuln.host[a.intern].to_s.match(search_term) } or
              vuln.attribute_names.any? { |a| vuln[a.intern].to_s.match(search_term) }
            )
          end
          reflist = vuln.refs.map { |r| r.name }
          if(vuln.service)
            # Skip this one if the user specified a port and it
            # doesn't match.
            next unless ports.empty? or ports.include? vuln.service.port
            # Same for service names
            next unless svcs.empty? or svcs.include?(vuln.service.name)
            print_status("Time: #{vuln.created_at} Vuln: host=#{host.address} name=#{vuln.name} refs=#{reflist.join(',')} #{(show_info && vuln.info) ? "info=#{vuln.info}" : ""}")

          else
            # This vuln has no service, so it can't match
            next unless ports.empty? and svcs.empty?
            print_status("Time: #{vuln.created_at} Vuln: host=#{host.address} name=#{vuln.name} refs=#{reflist.join(',')} #{(show_info && vuln.info) ? "info=#{vuln.info}" : ""}")
          end
          if set_rhosts
            addr = (host.scope ? host.address + '%' + host.scope : host.address)
            rhosts << addr
          end
        end
      end
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts
  }
  end

  def cmd_creds_help
    print_line
    print_line "With no sub-command, list credentials. If an address range is"
    print_line "given, show only credentials with logins on hosts within that"
    print_line "range."

    print_line
    print_line "Usage - Listing credentials:"
    print_line "  creds [filter options] [address range]"
    print_line
    print_line "Usage - Adding credentials:"
    print_line "  creds add-ntlm <user> <ntlm hash> [domain]"
    print_line "  creds add-password <user> <password> [realm] [realm-type]"
    print_line "  creds add-ssh-key <user> </path/to/id_rsa> [realm-type]"
    print_line "Where [realm type] can be one of:"
    Metasploit::Model::Realm::Key::SHORT_NAMES.each do |short, description|
      print_line "  #{short} - #{description}"
    end

    print_line
    print_line "General options"
    print_line "  -h,--help             Show this help information"
    print_line "  -o <file>             Send output to a file in csv format"
    print_line "  -d                    Delete one or more credentials"
    print_line
    print_line "Filter options for listing"
    print_line "  -P,--password <regex> List passwords that match this regex"
    print_line "  -p,--port <portspec>  List creds with logins on services matching this port spec"
    print_line "  -s <svc names>        List creds matching comma-separated service names"
    print_line "  -u,--user <regex>     List users that match this regex"
    print_line "  -t,--type <type>      List creds that match the following types: #{allowed_cred_types.join(',')}"
    print_line "  -O,--origins          List creds that match these origins"
    print_line "  -R,--rhosts           Set RHOSTS from the results of the search"

    print_line
    print_line "Examples, listing:"
    print_line "  creds               # Default, returns all credentials"
    print_line "  creds 1.2.3.4/24    # nmap host specification"
    print_line "  creds -p 22-25,445  # nmap port specification"
    print_line "  creds -s ssh,smb    # All creds associated with a login on SSH or SMB services"
    print_line "  creds -t ntlm       # All NTLM creds"
    print_line

    print_line
    print_line "Examples, adding:"
    print_line "  # Add a user with an NTLMHash"
    print_line "  creds add-ntlm alice 5cfe4c82d9ab8c66590f5b47cd6690f1:978a2e2e1dec9804c6b936f254727f9a"
    print_line "  # Add a user with a blank password and a domain"
    print_line "  creds add-password bob '' contosso"
    print_line "  # Add a user with an SSH key"
    print_line "  creds add-ssh-key root /root/.ssh/id_rsa"
    print_line

    print_line "Example, deleting:"
    print_line "  # Delete all SMB credentials"
    print_line "  creds -d -s smb"
    print_line
  end

  # @param private_type [Symbol] See `Metasploit::Credential::Creation#create_credential`
  # @param username [String]
  # @param password [String]
  # @param realm [String]
  # @param realm_type [String] A key in `Metasploit::Model::Realm::Key::SHORT_NAMES`
  def creds_add(private_type, username, password=nil, realm=nil, realm_type=nil)
    cred_data = {
      username: username,
      private_data: password,
      private_type: private_type,
      workspace_id: framework.db.workspace,
      origin_type: :import,
      filename: "msfconsole"
    }
    if realm.present?
      if realm_type.present?
        realm_key = Metasploit::Model::Realm::Key::SHORT_NAMES[realm_type]
        if realm_key.nil?
          valid = Metasploit::Model::Realm::Key::SHORT_NAMES.keys.map{|n|"'#{n}'"}.join(", ")
          print_error("Invalid realm type: #{realm_type}. Valid values: #{valid}")
          return
        end
      end
      realm_key ||= Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      cred_data.merge!(
        realm_value: realm,
        realm_key: realm_key
      )
    end

    begin
      create_credential(cred_data)
    rescue ActiveRecord::RecordInvalid => e
      print_error("Failed to add #{private_type}: #{e}")
    end
  end

  def creds_add_non_replayable_hash(*args)
    creds_add(:non_replayable_hash, *args)
  end

  def creds_add_ntlm_hash(*args)
    creds_add(:ntlm_hash, *args)
  end

  def creds_add_password(*args)
    creds_add(:password, *args)
  end

  def creds_add_ssh_key(username, *args)
    key_file, realm = args
    begin
      key_data = File.read(key_file)
    rescue ::Errno::EACCES, ::Errno::ENOENT => e
      print_error("Failed to add ssh key: #{e}")
    else
      creds_add(:ssh_key, username, key_data, realm)
    end
  end

  def creds_search(*args)
    host_ranges   = []
    origin_ranges = []
    port_ranges   = []
    svcs          = []
    rhosts        = []

    set_rhosts = false

    #cred_table_columns = [ 'host', 'port', 'user', 'pass', 'type', 'proof', 'active?' ]
    cred_table_columns = [ 'host', 'origin' , 'service', 'public', 'private', 'realm', 'private_type' ]
    user = nil
    delete_count = 0

    while (arg = args.shift)
      case arg
      when '-o'
        output_file = args.shift
        if (!output_file)
          print_error("Invalid output filename")
          return
        end
        output_file = ::File.expand_path(output_file)
      when "-p","--port"
        unless (arg_port_range(args.shift, port_ranges, true))
          return
        end
      when "-t","--type"
        ptype = args.shift
        if (!ptype)
          print_error("Argument required for -t")
          return
        end
      when "-s","--service"
        service = args.shift
        if (!service)
          print_error("Argument required for -s")
          return
        end
        svcs = service.split(/[\s]*,[\s]*/)
      when "-P","--password"
        pass = args.shift
        if (!pass)
          print_error("Argument required for -P")
          return
        end
      when "-u","--user"
        user = args.shift
        if (!user)
          print_error("Argument required for -u")
          return
        end
      when "-d"
        mode = :delete
      when '-R', '--rhosts'
        set_rhosts = true
      when '-O', '--origins'
        hosts = args.shift
        if !hosts
          print_error("Argument required for -O")
          return
        end
        arg_host_range(hosts, origin_ranges)
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
          return
        end
      end
    end

    # If we get here, we're searching.  Delete implies search

    if ptype
      type = case ptype
             when 'password'
               Metasploit::Credential::Password
             when 'hash'
               Metasploit::Credential::PasswordHash
             when 'ntlm'
               Metasploit::Credential::NTLMHash
             else
               print_error("Unrecognized credential type #{ptype} -- must be one of #{allowed_cred_types.join(',')}")
               return
             end
    end

    # normalize
    ports = port_ranges.flatten.uniq
    svcs.flatten!
    tbl_opts = {
      'Header'  => "Credentials",
      'Columns' => cred_table_columns
    }

    tbl = Rex::Text::Table.new(tbl_opts)

    ::ActiveRecord::Base.connection_pool.with_connection {
      query = Metasploit::Credential::Core.where( workspace_id: framework.db.workspace )
      query = query.includes(:private, :public, :logins).references(:private, :public, :logins)
      query = query.includes(logins: [ :service, { service: :host } ])

      if type.present?
        query = query.where(metasploit_credential_privates: { type: type })
      end

      if svcs.present?
        query = query.where(Mdm::Service[:name].in(svcs))
      end

      if ports.present?
        query = query.where(Mdm::Service[:port].in(ports))
      end

      if user.present?
        # If we have a user regex, only include those that match
        query = query.where('"metasploit_credential_publics"."username" ~* ?', user)
      end

      if pass.present?
        # If we have a password regex, only include those that match
        query = query.where('"metasploit_credential_privates"."data" ~* ?', pass)
      end

      if host_ranges.any? || ports.any? || svcs.any?
        # Only find Cores that have non-zero Logins if the user specified a
        # filter based on host, port, or service name
        query = query.where(Metasploit::Credential::Login[:id].not_eq(nil))
      end

      query.find_each do |core|

        # Exclude non-blank username creds if that's what we're after
        if user == "" && core.public && !(core.public.username.blank?)
          next
        end

        # Exclude non-blank password creds if that's what we're after
        if pass == "" && core.private && !(core.private.data.blank?)
          next
        end

        origin = ''
        if core.origin.kind_of?(Metasploit::Credential::Origin::Service)
          origin = core.origin.service.host.address
        elsif core.origin.kind_of?(Metasploit::Credential::Origin::Session)
          origin = core.origin.session.host.address
        end

        if !origin.empty? && origin_ranges.present? && !origin_ranges.any? {|range| range.include?(origin) }
          next
        end

        if core.logins.empty? && origin_ranges.empty?
          tbl << [
            "", # host
            "", # cred
            "", # service
            core.public,
            core.private,
            core.realm,
            core.private ? core.private.class.model_name.human : "",
          ]
        else
          core.logins.each do |login|
            # If none of this Core's associated Logins is for a host within
            # the user-supplied RangeWalker, then we don't have any reason to
            # print it out. However, we treat the absence of ranges as meaning
            # all hosts.
            if host_ranges.present? && !host_ranges.any? { |range| range.include?(login.service.host.address) }
              next
            end

            row = [ login.service.host.address ]
            row << origin
            rhosts << login.service.host.address
            if login.service.name.present?
              row << "#{login.service.port}/#{login.service.proto} (#{login.service.name})"
            else
              row << "#{login.service.port}/#{login.service.proto}"
            end

            row += [
              core.public,
              core.private,
              core.realm,
              core.private ? core.private.class.model_name.human : "",
            ]
            tbl << row
          end
        end
        if mode == :delete
          core.destroy
          delete_count += 1
        end
      end

      if output_file.nil?
        print_line(tbl.to_s)
      else
        # create the output file
        ::File.open(output_file, "wb") { |f| f.write(tbl.to_csv) }
        print_status("Wrote creds to #{output_file}")
      end

      # Finally, handle the case where the user wants the resulting list
      # of hosts to go into RHOSTS.
      set_rhosts_from_addrs(rhosts.uniq) if set_rhosts
      print_status("Deleted #{delete_count} creds") if delete_count > 0
    }
  end

  #
  # Can return return active or all, on a certain host or range, on a
  # certain port or range, and/or on a service name.
  #
  def cmd_creds(*args)
    return unless active?

    # Short-circuit help
    if args.delete "-h"
      cmd_creds_help
      return
    end

    subcommand = args.shift
    case subcommand
    when "add-ntlm"
      creds_add_ntlm_hash(*args)
    when "add-password"
      creds_add_password(*args)
    when "add-hash"
      creds_add_non_replayable_hash(*args)
    when "add-ssh-key"
      creds_add_ssh_key(*args)
    else
      # then it's not actually a subcommand
      args.unshift(subcommand) if subcommand
      creds_search(*args)
    end

  end

  def cmd_creds_tabs(str, words)
    case words.length
    when 1
      # subcommands
      tabs = [ 'add-ntlm', 'add-password', 'add-hash', 'add-ssh-key', ]
    when 2
      tabs = if words[1] == 'add-ssh-key'
               tab_complete_filenames(str, words)
             else
               []
             end
    #when 5
    #  tabs = Metasploit::Model::Realm::Key::SHORT_NAMES.keys
    else
      tabs = []
    end
    return tabs
  end

  def cmd_notes_help
    print_line "Usage: notes [-h] [-t <type1,type2>] [-n <data string>] [-a] [addr range]"
    print_line
    print_line "  -a,--add                  Add a note to the list of addresses, instead of listing"
    print_line "  -d,--delete               Delete the hosts instead of searching"
    print_line "  -n,--note <data>          Set the data for a new note (only with -a)"
    print_line "  -t <type1,type2>          Search for a list of types"
    print_line "  -h,--help                 Show this help information"
    print_line "  -R,--rhosts               Set RHOSTS from the results of the search"
    print_line "  -S,--search               Regular expression to match for search"
    print_line "  -o,--output               Save the notes to a csv file"
    print_line "  --sort <field1,field2>    Fields to sort by (case sensitive)"
    print_line
    print_line "Examples:"
    print_line "  notes --add -t apps -n 'winzip' 10.1.1.34 10.1.20.41"
    print_line "  notes -t smb.fingerprint 10.1.1.34 10.1.20.41"
    print_line "  notes -S 'nmap.nse.(http|rtsp)' --sort type,output"
    print_line
  end

  def cmd_notes(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    mode = :search
    data = nil
    types = nil
    set_rhosts = false

    host_ranges = []
    rhosts      = []
    search_term = nil
    out_file    = nil

    while (arg = args.shift)
      case arg
      when '-a','--add'
        mode = :add
      when '-d','--delete'
        mode = :delete
      when '-n','--note'
        data = args.shift
        if(!data)
          print_error("Can't make a note with no data")
          return
        end
      when '-t'
        typelist = args.shift
        if(!typelist)
          print_error("Invalid type list")
          return
        end
        types = typelist.strip().split(",")
      when '-R', '--rhosts'
        set_rhosts = true
      when '-S', '--search'
        search_term = /#{args.shift}/nmi
      when '--sort'
        sort_term = args.shift
      when '-o', '--output'
        out_file = args.shift
      when '-h','--help'
        cmd_notes_help
        return
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
          return
        end
      end
    end

    if mode == :add
      if types.nil? or types.size != 1
        print_error("Exactly one note type is required")
        return
      end
      type = types.first
      host_ranges.each { |range|
        range.each { |addr|
          host = framework.db.find_or_create_host(:host => addr)
          break if not host
          note = framework.db.find_or_create_note(:host => host, :type => type, :data => data)
          break if not note
          print_status("Time: #{note.created_at} Note: host=#{host.address} type=#{note.ntype} data=#{note.data}")
        }
      }
      return
    end

    note_list = []
    delete_count = 0
    # No host specified - collect all notes
    if host_ranges.empty?
      note_list = framework.db.notes.dup
    # Collect notes of specified hosts
    else
      each_host_range_chunk(host_ranges) do |host_search|
        framework.db.hosts(framework.db.workspace, false, host_search).each do |host|
          note_list.concat(host.notes)
        end
      end
    end
    if search_term
      note_list = note_list.select do |n|
        n.attribute_names.any? { |a| n[a.intern].to_s.match(search_term) }
      end
    end

    # Sort the notes based on the sort_term provided
    if sort_term != nil
      sort_terms = sort_term.split(",")
      note_list.sort_by! do |note|
        orderlist = []
        sort_terms.each do |term|
          term = "ntype" if term == "type"
          term = "created_at" if term == "Time"
          if term == nil
            orderlist << ""
          elsif term == "service"
            if note.service != nil
              orderlist << make_sortable(note.service.name)
            end
          elsif term == "port"
            if note.service != nil
              orderlist << make_sortable(note.service.port)
            end
          elsif term == "output"
            orderlist << make_sortable(note.data["output"])
          elsif note.respond_to?(term, true)
            orderlist << make_sortable(note.send(term))
          elsif note.respond_to?(term.to_sym, true)
            orderlist << make_sortable(note.send(term.to_sym))
          elsif note.respond_to?("data", true) && note.send("data").respond_to?(term, true)
            orderlist << make_sortable(note.send("data").send(term))
          elsif note.respond_to?("data", true) && note.send("data").respond_to?(term.to_sym, true)
            orderlist << make_sortable(note.send("data").send(term.to_sym))
          else
            orderlist << ""
          end
        end
        orderlist
      end
    end

    # Now display them
    csv_table = Rex::Text::Table.new(
      'Header'  => 'Notes',
      'Indent'  => 1,
      'Columns' => ['Time', 'Host', 'Service', 'Port', 'Protocol', 'Type', 'Data']
    )

    note_list.each do |note|
      next if(types and types.index(note.ntype).nil?)
      csv_note = []
      msg = "Time: #{note.created_at} Note:"
      csv_note << note.created_at if out_file
      if (note.host)
        host = note.host
        msg << " host=#{note.host.address}"
        csv_note << note.host.address if out_file
        if set_rhosts
          addr = (host.scope ? host.address + '%' + host.scope : host.address )
          rhosts << addr
        end
      else
        csv_note << ''
      end
      if (note.service)
        msg << " service=#{note.service.name}" if note.service.name
        csv_note << note.service.name || '' if out_file
        msg << " port=#{note.service.port}" if note.service.port
        csv_note << note.service.port || '' if out_file
        msg << " protocol=#{note.service.proto}" if note.service.proto
        csv_note << note.service.proto || '' if out_file
      else
        if out_file
          csv_note << '' # For the Service field
          csv_note << '' # For the Port field
          csv_note << '' # For the Protocol field
        end
      end
      msg << " type=#{note.ntype} data=#{note.data.inspect}"
      if out_file
        csv_note << note.ntype
        csv_note << note.data.inspect
      end
      print_status(msg)
      if out_file
        csv_table << csv_note
      end
      if mode == :delete
        note.destroy
        delete_count += 1
      end
    end

    if out_file
      save_csv_notes(out_file, csv_table)
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts

    print_status("Deleted #{delete_count} notes") if delete_count > 0
  }
  end

  def save_csv_notes(fpath, csv_table)
    begin
      File.open(fpath, 'wb') do |f|
        f.write(csv_table.to_csv)
      end
      print_status("Notes saved as #{fpath}")
    rescue Errno::EACCES => e
      print_error("Unable to save notes. #{e.message}")
    end
  end

  def make_sortable(input)
    case input
    when String
      input = input.downcase
    when Fixnum
      input = "%016" % input
    when Time
      input = input.strftime("%Y%m%d%H%M%S%L")
    when NilClass
      input = ""
    else
      input = input.inspect.downcase
    end
    input
  end

  def cmd_loot_help
    print_line "Usage: loot <options>"
    print_line " Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]"
    print_line "  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] [-t [type]"
    print_line "  Del: loot -d [addr1 addr2 ...]"
    print_line
    print_line "  -a,--add          Add loot to the list of addresses, instead of listing"
    print_line "  -d,--delete       Delete *all* loot matching host and type"
    print_line "  -f,--file         File with contents of the loot to add"
    print_line "  -i,--info         Info of the loot to add"
    print_line "  -t <type1,type2>  Search for a list of types"
    print_line "  -h,--help         Show this help information"
    print_line "  -S,--search       Search string to filter by"
    print_line
  end

  def cmd_loot(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    mode = :search
    host_ranges = []
    types = nil
    delete_count = 0
    search_term = nil
    file = nil
    name = nil
    info = nil

    while (arg = args.shift)
      case arg
        when '-a','--add'
          mode = :add
        when '-d','--delete'
          mode = :delete
        when '-f','--file'
          filename = args.shift
          if(!filename)
            print_error("Can't make loot with no filename")
            return
          end
          if (!File.exist?(filename) or !File.readable?(filename))
            print_error("Can't read file")
            return
          end
        when '-i','--info'
          info = args.shift
          if(!info)
            print_error("Can't make loot with no info")
            return
          end
        when '-t'
          typelist = args.shift
          if(!typelist)
            print_error("Invalid type list")
            return
          end
          types = typelist.strip().split(",")
        when '-S', '--search'
          search_term = /#{args.shift}/nmi
        when '-h','--help'
          cmd_loot_help
          return
        else
          # Anything that wasn't an option is a host to search for
          unless (arg_host_range(arg, host_ranges))
            return
          end
      end
    end

    tbl = Rex::Text::Table.new({
        'Header'  => "Loot",
        'Columns' => [ 'host', 'service', 'type', 'name', 'content', 'info', 'path' ],
      })

    # Sentinal value meaning all
    host_ranges.push(nil) if host_ranges.empty?

  if mode == :add
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
    host_ranges.each do |range|
      range.each do |host|
        file = File.open(filename, "rb")
        contents = file.read
        lootfile = framework.db.find_or_create_loot(:type => type, :host => host, :info => info, :data => contents, :path => filename, :name => name)
        print_status("Added loot for #{host} (#{lootfile})")
      end
    end
    return
  end

    each_host_range_chunk(host_ranges) do |host_search|
      framework.db.hosts(framework.db.workspace, false, host_search).each do |host|
        host.loots.each do |loot|
          next if(types and types.index(loot.ltype).nil?)
          if search_term
          next unless(
            loot.attribute_names.any? { |a| loot[a.intern].to_s.match(search_term) } or
            loot.host.attribute_names.any? { |a| loot.host[a.intern].to_s.match(search_term) }
          )
          end
          row = []
          row.push( (loot.host ? loot.host.address : "") )
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
          if (mode == :delete)
            loot.destroy
            delete_count += 1
          end
        end
      end
    end

    # Handle hostless loot
    if host_ranges.compact.empty? # Wasn't a host search
      hostless_loot = framework.db.loots.where(host_id: nil)
      hostless_loot.each do |loot|
        row = []
        row.push("")
        row.push("")
        row.push(loot.ltype)
        row.push(loot.name || "")
        row.push(loot.content_type)
        row.push(loot.info || "")
        row.push(loot.path)
        tbl << row
        if (mode == :delete)
          loot.destroy
          delete_count += 1
        end
      end
    end

    print_line
    print_line(tbl.to_s)
    print_status("Deleted #{delete_count} loots") if delete_count > 0
  }
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
    print_line "    IP Address List"
    print_line "    IP360 ASPL"
    print_line "    IP360 XML v3"
    print_line "    Libpcap Packet Capture"
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
    print_line "    OpenVAS XML"
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
  ::ActiveRecord::Base.connection_pool.with_connection {
    if args.include?("-h") || ! (args && args.length > 0)
      cmd_db_import_help
      return
    end
    args.each { |glob|
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
          framework.db.import_file(:filename => filename) do |type,data|
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

        rescue Msf::DBImportError
          print_error("Failed to import #{filename}: #{$!}")
          elog("Failed to import #{filename}: #{$!.class}: #{$!}")
          dlog("Call stack: #{$@.join("\n")}", LEV_3)
          next
        rescue REXML::ParseException => e
          print_error("Failed to import #{filename} due to malformed XML:")
          print_error("#{e.class}: #{e}")
          elog("Failed to import #{filename}: #{e.class}: #{e}")
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
  ::ActiveRecord::Base.connection_pool.with_connection {

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
    exporter = ::Msf::DBManager::Export.new(framework.db.workspace)

    exporter.send("to_#{format}_file".intern,output) do |mtype, mstatus, mname|
      if mtype == :status
        if mstatus == "start"
          print_status("    >> Starting export of #{mname}")
        end
        if mstatus == "complete"
          print_status("    >> Finished export of #{mname}")
        end
      end
    end
    print_status("Finished export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
  }
  end

  #
  # Import Nmap data from a file
  #
  def cmd_db_nmap(*args)
    return unless active?
  ::ActiveRecord::Base.connection_pool.with_connection {
    if (args.length == 0)
      print_status("Usage: db_nmap [--save | [--help | -h]] [nmap options]")
      return
    end
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

    nmap =
      Rex::FileUtils.find_full_path("nmap") ||
      Rex::FileUtils.find_full_path("nmap.exe")

    if (not nmap)
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

      begin
        nmap_pipe = ::Open3::popen3([nmap, 'nmap'], *arguments)
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
          end
        end

        temp_nmap_threads.map {|t| t.join rescue nil}
        nmap_pipe.each {|p| p.close rescue nil}
      rescue ::IOError
      end

      framework.db.import_nmap_xml_file(:filename => fd.path)

      print_status("Saved NMAP XML results to #{fd.path}") if save
    ensure
      fd.close
      fd.unlink unless save
    end
  }
  end

  def cmd_db_nmap_help
    nmap =
        Rex::FileUtils.find_full_path('nmap') ||
        Rex::FileUtils.find_full_path('nmap.exe')

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
    nmap =
        Rex::FileUtils.find_full_path('nmap') ||
        Rex::FileUtils.find_full_path('nmap.exe')

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

    tabs
  end

  #
  # Database management
  #
  def db_check_driver
    if(not framework.db.driver)
      print_error("No database driver installed. Try 'gem install pg'")
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
      cdb = ''
      ::ActiveRecord::Base.connection_pool.with_connection do |conn|
        if conn.respond_to?(:current_database)
          cdb = conn.current_database
        end
      end
      print_status("#{framework.db.driver} connected to #{cdb}")
    else
      print_status("#{framework.db.driver} selected, no connection")
    end
  end

  def cmd_db_connect_help
    # Help is specific to each driver
    cmd_db_connect("-h")
  end

  def cmd_db_connect(*args)
    return if not db_check_driver
    if args[0] != '-h' && framework.db.connection_established?
      cdb = ''
      ::ActiveRecord::Base.connection_pool.with_connection do |conn|
        if conn.respond_to?(:current_database)
          cdb = conn.current_database
        end
      end
      print_error("#{framework.db.driver} already connected to #{cdb}")
      print_error('Run db_disconnect first if you wish to connect to a different database')
      return
    end
    if (args[0] == "-y")
      if (args[1] and not ::File.exist? ::File.expand_path(args[1]))
        print_error("File not found")
        return
      end
      file = args[1] || ::File.join(Msf::Config.get_config_root, "database.yml")
      file = ::File.expand_path(file)
      if (::File.exist? file)
        db = YAML.load(::File.read(file))['production']
        framework.db.connect(db)

        if framework.db.active and not framework.db.modules_cached
          print_status("Rebuilding the module cache in the background...")
          framework.threads.spawn("ModuleCacheRebuild", true) do
            framework.db.update_all_module_details
          end
        end

        return
      end
    end
    meth = "db_connect_#{framework.db.driver}"
    if(self.respond_to?(meth, true))
      self.send(meth, *args)
      if framework.db.active and not framework.db.modules_cached
        print_status("Rebuilding the module cache in the background...")
        framework.threads.spawn("ModuleCacheRebuild", true) do
          framework.db.update_all_module_details
        end
      end
    else
      print_error("This database driver #{framework.db.driver} is not currently supported")
    end
  end

  def cmd_db_disconnect_help
    print_line "Usage: db_disconnect"
    print_line
    print_line "Disconnect from the database."
    print_line
  end

  def cmd_db_disconnect(*args)
    return if not db_check_driver

    if(args[0] and (args[0] == "-h" || args[0] == "--help"))
      cmd_db_disconnect_help
      return
    end

    if (framework.db)
      framework.db.disconnect()
    end
  end

  def cmd_db_rebuild_cache
    unless framework.db.active
      print_error("The database is not connected")
      return
    end

    print_status("Purging and rebuilding the module cache in the background...")
    framework.threads.spawn("ModuleCacheRebuild", true) do
      framework.db.purge_all_module_details
      framework.db.update_all_module_details
    end
  end

  def cmd_db_rebuild_cache_help
    print_line "Usage: db_rebuild_cache"
    print_line
    print_line "Purge and rebuild the SQL module cache."
    print_line
  end

  #
  # Set RHOSTS in the +active_module+'s (or global if none) datastore from an array of addresses
  #
  # This stores all the addresses to a temporary file and utilizes the
  # <pre>file:/tmp/filename</pre> syntax to confer the addrs.  +rhosts+
  # should be an Array.  NOTE: the temporary file is *not* deleted
  # automatically.
  #
  def set_rhosts_from_addrs(rhosts)
    if rhosts.empty?
      print_status("The list is empty, cowardly refusing to set RHOSTS")
      return
    end
    if active_module
      mydatastore = active_module.datastore
    else
      # if there is no module in use set the list to the global variable
      mydatastore = self.framework.datastore
    end

    if rhosts.length > 5
      # Lots of hosts makes 'show options' wrap which is difficult to
      # read, store to a temp file
      rhosts_file = Rex::Quickfile.new("msf-db-rhosts-")
      mydatastore['RHOSTS'] = 'file:'+rhosts_file.path
      # create the output file and assign it to the RHOSTS variable
      rhosts_file.write(rhosts.join("\n")+"\n")
      rhosts_file.close
    else
      # For short lists, just set it directly
      mydatastore['RHOSTS'] = rhosts.join(" ")
    end

    print_line "RHOSTS => #{mydatastore['RHOSTS']}"
    print_line
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

  #
  # Database management: Postgres
  #

  #
  # Connect to an existing Postgres database
  #
  def db_connect_postgresql(*args)
    if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
      print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
      print_status("      OR: db_connect -y [path/to/database.yml]")
      print_status("Examples:")
      print_status("       db_connect user@metasploit3")
      print_status("       db_connect user:pass@192.168.0.2/metasploit3")
      print_status("       db_connect user:pass@192.168.0.2:1500/metasploit3")
      return
    end

    info = db_parse_db_uri_postgresql(args[0])
    opts = { 'adapter' => 'postgresql' }

    opts['username'] = info[:user] if (info[:user])
    opts['password'] = info[:pass] if (info[:pass])
    opts['database'] = info[:name]
    opts['host'] = info[:host] if (info[:host])
    opts['port'] = info[:port] if (info[:port])

    opts['pass'] ||= ''

    # Do a little legwork to find the real database socket
    if(! opts['host'])
      while(true)
        done = false
        dirs = %W{ /var/run/postgresql /tmp }
        dirs.each do |dir|
          if(::File.directory?(dir))
            d = ::Dir.new(dir)
            d.entries.grep(/^\.s\.PGSQL.(\d+)$/).each do |ent|
              opts['port'] = ent.split('.')[-1].to_i
              opts['host'] = dir
              done = true
              break
            end
          end
          break if done
        end
        break
      end
    end

    # Default to loopback
    if(! opts['host'])
      opts['host'] = '127.0.0.1'
    end

    if (not framework.db.connect(opts))
      raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
    end
  end

  def db_parse_db_uri_postgresql(path)
    res = {}
    if (path)
      auth, dest = path.split('@')
      (dest = auth and auth = nil) if not dest
      res[:user],res[:pass] = auth.split(':') if auth
      targ,name = dest.split('/')
      (name = targ and targ = nil) if not name
      res[:host],res[:port] = targ.split(':') if targ
    end
    res[:name] = name || 'metasploit3'
    res
  end

  #
  # Miscellaneous option helpers
  #

  # Parse +arg+ into a {Rex::Socket::RangeWalker} and append the result into +host_ranges+
  #
  # @note This modifies +host_ranges+ in place
  #
  # @param arg [String] The thing to turn into a RangeWalker
  # @param host_ranges [Array] The array of ranges to append
  # @param required [Boolean] Whether an empty +arg+ should be an error
  # @return [Boolean] true if parsing was successful or false otherwise
  def arg_host_range(arg, host_ranges, required=false)
    if (!arg and required)
      print_error("Missing required host argument")
      return false
    end
    begin
      rw = Rex::Socket::RangeWalker.new(arg)
    rescue
      print_error("Invalid host parameter, #{arg}.")
      return false
    end

    if rw.valid?
      host_ranges << rw
    else
      print_error("Invalid host parameter, #{arg}.")
      return false
    end
    return true
  end

  #
  # Parse +arg+ into an array of ports and append the result into +port_ranges+
  #
  # Returns true if parsing was successful or nil otherwise.
  #
  # NOTE: This modifies +port_ranges+
  #
  def arg_port_range(arg, port_ranges, required=false)
    if (!arg and required)
      print_error("Argument required for -p")
      return
    end
    begin
      port_ranges << Rex::Socket.portspec_to_portlist(arg)
    rescue
      print_error("Invalid port parameter, #{arg}.")
      return
    end
    return true
  end

  #
  # Takes +host_ranges+, an Array of RangeWalkers, and chunks it up into
  # blocks of 1024.
  #
  def each_host_range_chunk(host_ranges, &block)
    # Chunk it up and do the query in batches. The naive implementation
    # uses so much memory for a /8 that it's basically unusable (1.6
    # billion IP addresses take a rather long time to allocate).
    # Chunking has roughly the same perfomance for small batches, so
    # don't worry about it too much.
    host_ranges.each do |range|
      if range.nil? or range.length.nil?
        chunk = nil
        end_of_range = true
      else
        chunk = []
        end_of_range = false
        # Set up this chunk of hosts to search for
        while chunk.length < 1024 and chunk.length < range.length
          n = range.next_ip
          if n.nil?
            end_of_range = true
            break
          end
          chunk << n
        end
      end

      # The block will do some
      yield chunk

      # Restart the loop with the same RangeWalker if we didn't get
      # to the end of it in this chunk.
      redo unless end_of_range
    end
  end

end

end end end end
