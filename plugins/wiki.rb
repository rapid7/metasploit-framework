##
#
# This plugin requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
##

module Msf

###
#
# This plugin extends the Rex::Text::Table class and provides commands
# that output database information for the current workspace in a wiki
# friendly format
#
# @author Trenton Ivey
#  * *email:* ("trenton.ivey@example.com").gsub(/example/,"gmail")
#  * *github:* kn0
#  * *twitter:* trentonivey
###
class Plugin::Wiki < Msf::Plugin

  ###
  #
  # This class implements a command dispatcher that provides commands to
  # output database information in a wiki friendly format.
  #
  ###
  class WikiCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    #
    # The dispatcher's name.
    #
    def name
      "Wiki"
    end

    #
    # Returns the hash of commands supported by the wiki dispatcher.
    #
    def commands
      {
        "dokuwiki" => "Outputs data from the current workspace in dokuwiki markup.",
        "mediawiki" => "Outputs data from the current workspace in mediawiki markup."
      }
    end

    #
    # Outputs database entries as Dokuwiki formatted text by passing the
    # arguments to the wiki method with a wiki_type of 'dokuwiki'
    # @param [Array<String>] args the arguments passed when the command is
    #   called
    # @see #wiki
    #
    def cmd_dokuwiki(*args)
      wiki("dokuwiki", *args)
    end

    #
    # Outputs database entries as Mediawiki formatted text by passing the
    # arguments to the wiki method with a wiki_type of 'mediawiki'
    # @param [Array<String>] args the arguments passed when the command is
    #   called
    # @see #wiki
    #
    def cmd_mediawiki(*args)
      wiki("mediawiki", *args)
    end

    #
    # This method parses arguments passed from the wiki output commands
    # and then formats and displays or saves text according to the
    # provided wiki type
    #
    # @param [String] wiki_type selects the wiki markup lanuguage output to
    #   use, it can be:
    #   * dokuwiki
    #   * mediawiki
    #
    # @param [Array<String>] args the arguments passed when the command is
    #  called
    #
    def wiki(wiki_type, *args)
      # Create a table options hash
      tbl_opts = {}
      # Set some default options for the table hash
      tbl_opts[:hosts] = []
      tbl_opts[:links] = false
      tbl_opts[:wiki_type] = wiki_type
      tbl_opts[:heading_size] = 5
      case wiki_type
      when "dokuwiki"
        tbl_opts[:namespace] = 'notes:targets:hosts:'
      else
        tbl_opts[:namespace] = ''
      end

      # Get the table we should be looking at
      command = args.shift
      if command.nil? or not(["creds","hosts","loot","services","vulns"].include?(command.downcase))
        usage(wiki_type)
        return
      end

      # Parse the rest of the arguments
      while (arg = args.shift)
        case arg
        when '-o','--output'
          tbl_opts[:file_name] = next_opt(args)
        when '-h','--help'
          usage(wiki_type)
          return
        when '-l', '-L', '--link', '--links'
          tbl_opts[:links] = true
        when '-n', '-N', '--namespace'
          tbl_opts[:namespace] = next_opt(args)
        when '-p', '-P', '--port', '--ports'
          tbl_opts[:ports] = next_opts(args)
          tbl_opts[:ports].map! {|p| p.to_i}
        when '-s', '-S', '--search'
          tbl_opts[:search] = next_opt(args)
        when '-i', '-I', '--heading-size'
          heading_size = next_opt(args)
          tbl_opts[:heading_size] = heading_size.to_i unless heading_size.nil?
        else
          # Assume it is a host
          rw = Rex::Socket::RangeWalker.new(arg)
          if rw.valid?
            rw.each do |ip|
              tbl_opts[:hosts] << ip
            end
          else
            print_warning "#{arg} is an invalid hostname"
          end
        end
      end

      # Create an Array to hold a list of tables that we want to show
      outputs = []

      # Output the table
      if respond_to? "#{command}_to_table", true
        table = send "#{command}_to_table", tbl_opts
        if table.respond_to? "to_#{wiki_type}", true
          if tbl_opts[:file_name]
            print_status("Wrote the #{command} table to a file as a #{wiki_type} formatted table")
            File.open(tbl_opts[:file_name],"wb") {|f|
              f.write(table.send  "to_#{wiki_type}")
            }
          else
            print_line table.send  "to_#{wiki_type}"
          end
          return
        end
      end
      usage(wiki_type)
    end

    #
    # Gets the next set of arguments when parsing command options
    #
    # *Note:* This will modify the provided argument list
    #
    # @param [Array] args the list of unparsed arguments
    # @return [Array] the unique list of items before the next '-' in the
    #   provided array
    #
    def next_opts(args)
      opts = []
      while ( opt = args.shift )
        if opt =~ /^-/
          args.unshift opt
          break
        end
        opts.concat ( opt.split(',') )
      end
      return opts.uniq
    end

    #
    # Gets the next argument when parsing command options
    #
    # *Note:* This will modify the provided argument list
    #
    # @param [Array] args the list of unparsed arguments
    # @return [String, nil] the argument or nil if the argument starts with a '-'
    #
    def next_opt(args)
      return nil if args[0] =~ /^-/
      args.shift
    end

    #
    # Outputs the help message
    #
    # @param [String] cmd_name the type of the wiki output command to display
    #   help for
    #
    def usage(cmd_name = "<wiki cmd>")
      print_line "Usage: #{cmd_name} <table> [options] [IP1 IP2,IPn]"
      print_line
      print_line "The first argument must be the type of table to retrieve:"
      print_line "  creds, hosts, loot, services, vulns"
      print_line
      print_line "OPTIONS:"
      print_line "  -l,--link                Enables links for host addresses"
      print_line "  -n,--namespace <ns>      Changes the default namespace for host links"
      print_line "  -o,--output <file>       Write output to a file"
      print_line "  -p,--port <ports>        Only return results that relate to given ports"
      print_line "  -s,--search <search>     Only show results that match the provided text"
      print_line "  -i,--heading-size <1-6>  Changes the heading size"
      print_line "  -h,--help                Displays this menu"
      print_line
    end

    #
    # Outputs credentials in the database (within the current workspace) as a Rex table object
    # @param [Hash] opts
    # @option opts [Array<String>] :hosts contains list of hosts used to limit results
    # @option opts [Array<Integer>] :ports contains list of ports used to limit results
    # @option opts [String] :search limits results to those containing a provided string
    # @return [Rex::Text::Table] table containing credentials
    #
    def creds_to_table(opts = {})
      tbl = Rex::Text::Table.new({'Columns' => ['host','port','user','pass','type','proof','active?']})
      tbl.header = 'Credentials'
      tbl.headeri = opts[:heading_size]
      framework.db.creds.each do |cred|
        unless opts[:hosts].nil? or opts[:hosts].empty?
          next unless opts[:hosts].include? cred.service.host.address
        end
        unless opts[:ports].nil?
          next unless opts[:ports].any? {|p| cred.service.port.eql? p}
        end
        address = cred.service.host.address
        address = to_wikilink(address,opts[:namespace]) if opts[:links]
        row = [
          address,
          cred.service.port,
          cred.user,
          cred.pass,
          cred.ptype,
          cred.proof,
          cred.active
        ]
        if opts[:search]
          tbl << row if row.any? {|r| /#{opts[:search]}/i.match r.to_s}
        else
          tbl << row
        end
      end
      return tbl
    end

    #
    # Outputs host information stored in the database (within the current
    #   workspace) as a Rex table object
    # @param [Hash] opts
    # @option opts [Array<String>] :hosts contains list of hosts used to limit results
    # @option opts [Array<String>] :ports contains list of ports used to limit results
    # @option opts [String] :search limits results to those containing a provided string
    # @return [Rex::Text::Table] table containing credentials
    #
    def hosts_to_table(opts = {})
      tbl = Rex::Text::Table.new({'Columns' => ['address','mac','name','os_name','os_flavor','os_sp','purpose','info','comments']})
      tbl.header = 'Hosts'
      tbl.headeri = opts[:heading_size]
      framework.db.hosts.each do |host|
        unless opts[:hosts].nil? or opts[:hosts].empty?
          next unless opts[:hosts].include? host.address
        end
        unless opts[:ports].nil?
          next unless (host.services.map{|s| s[:port]}).any? {|p| opts[:ports].include? p}
        end
        address = host.address
        address = to_wikilink(address,opts[:namespace]) if opts[:links]
        row = [
          address,
          host.mac,
          host.name,
          host.os_name,
          host.os_flavor,
          host.os_sp,
          host.purpose,
          host.info,
          host.comments
        ]
        if opts[:search]
          tbl << row if row.any? {|r| /#{opts[:search]}/i.match r.to_s}
        else
          tbl << row
        end
      end
      return tbl
    end

    #
    # Outputs loot information stored in the database (within the current
    #   workspace) as a Rex table object
    # @param [Hash] opts
    # @option opts [Array<String>] :hosts contains list of hosts used to limit results
    # @option opts [Array<String>] :ports contains list of ports used to limit results
    # @option opts [String] :search limits results to those containing a provided string
    # @return [Rex::Text::Table] table containing credentials
    #
    def loot_to_table(opts = {})
      tbl = Rex::Text::Table.new({'Columns' => ['host','service','type','name','content','info','path']})
      tbl.header = 'Loot'
      tbl.headeri = opts[:heading_size]
      framework.db.loots.each do |loot|
        unless opts[:hosts].nil? or opts[:hosts].empty?
          next unless opts[:hosts].include? loot.host.address
        end
        unless opts[:ports].nil? or opts[:ports].empty?
          next if loot.service.nil? or loot.service.port.nil? or not opts[:ports].include? loot.service.port
        end
        if loot.service
          svc = (loot.service.name ? loot.service.name : "#{loot.service.port}/#{loot.service.proto}")
        end
        address = loot.host.address
        address = to_wikilink(address,opts[:namespace]) if opts[:links]
        row = [
          address,
          svc || "",
          loot.ltype,
          loot.name,
          loot.content_type,
          loot.info,
          loot.path
        ]
        if opts[:search]
          tbl << row if row.any? {|r| /#{opts[:search]}/i.match r.to_s}
        else
          tbl << row
        end
      end
      return tbl
    end

    #
    # Outputs service information stored in the database (within the current
    # workspace) as a Rex table object
    # @param [Hash] opts
    # @option opts [Array<String>] :hosts contains list of hosts used to limit results
    # @option opts [Array<String>] :ports contains list of ports used to limit results
    # @option opts [String] :search limits results to those containing a provided string
    # @return [Rex::Text::Table] table containing credentials
    #
    def services_to_table(opts = {})
      tbl = Rex::Text::Table.new({'Columns' => ['host','port','proto','name','state','info']})
      tbl.header = 'Services'
      tbl.headeri = opts[:heading_size]
      framework.db.services.each do |service|
        unless opts[:hosts].nil? or opts[:hosts].empty?
          next unless opts[:hosts].include? service.host.address
        end
        unless opts[:ports].nil? or opts[:ports].empty?
          next unless opts[:ports].any? {|p| service[:port].eql? p}
        end
        address = service.host.address
        address = to_wikilink(address,opts[:namespace]) if opts[:links]
        row = [
          address,
          service.port,
          service.proto,
          service.name,
          service.state,
          service.info
        ]
        if opts[:search]
          tbl << row if row.any? {|r| /#{opts[:search]}/i.match r.to_s}
        else
          tbl << row
        end
      end
      return tbl
    end

    #
    # Outputs vulnerability information stored in the database (within the current
    # workspace) as a Rex table object
    # @param [Hash] opts
    # @option opts [Array<String>] :hosts contains list of hosts used to limit results
    # @option opts [Array<String>] :ports contains list of ports used to limit results
    # @option opts [String] :search limits results to those containing a provided string
    # @return [Rex::Text::Table] table containing credentials
    #
    def vulns_to_table(opts = {})
      tbl = Rex::Text::Table.new({'Columns' => ['Title','Host','Port','Info','Detail Count','Attempt Count','Exploited At','Updated At']})
      tbl.header = 'Vulns'
      tbl.headeri = opts[:heading_size]
      framework.db.vulns.each do |vuln|
        unless opts[:hosts].nil? or opts[:hosts].empty?
          next unless opts[:hosts].include? vuln.host.address
        end
        unless opts[:ports].nil? or opts[:ports].empty?
          next unless opts[:ports].any? {|p| vuln.service.port.eql? p}
        end
        address = vuln.host.address
        address = to_wikilink(address,opts[:namespace]) if opts[:links]
        row = [
          vuln.name,
          address,
          (vuln.service ? vuln.service.port : ""),
          vuln.info,
          vuln.vuln_detail_count,
          vuln.vuln_attempt_count,
          vuln.exploited_at,
          vuln.updated_at,
        ]
        if opts[:search]
          tbl << row if row.any? {|r| /#{opts[:search]}/i.match r.to_s}
        else
          tbl << row
        end
      end
      return tbl
    end

    #
    # Converts a value to a wiki link
    # @param [String] text value to convert to a link
    # @param [String] namespace optional namespace to set for the link
    # @return [String] the formated wiki link
    def to_wikilink(text,namespace = "")
      return "[[" + namespace + text + "]]"
    end

  end


  #
  # Plugin Initialization
  #


  #
  # Constructs a new instance of the plugin and registers the console
  # dispatcher. It also extends Rex by adding the following methods:
  #   * Rex::Text::Table.to_dokuwiki
  #   * Rex::Text::Table.to_mediawiki
  #
  def initialize(framework, opts)
    super

    # Extend Rex::Text::Table class so it can output wiki formats
    add_dokuwiki_to_rex
    add_mediawiki_to_rex

    # Add the console dispatcher
    add_console_dispatcher(WikiCommandDispatcher)
  end

  #
  # The cleanup routine removes the methods added to Rex by the plugin
  # initialization and then removes the console dispatcher
  #
  def cleanup
    # Cleanup methods added to Rex::Text::Table
    Rex::Text::Table.class_eval { undef :to_dokuwiki }
    Rex::Text::Table.class_eval { undef :to_mediawiki }
    # Deregister the console dispatcher
    remove_console_dispatcher('Wiki')
  end

  #
  # Returns the plugin's name.
  #
  def name
    "wiki"
  end

  #
  # This method returns a brief description of the plugin.  It should be no
  # more than 60 characters, but there are no hard limits.
  #
  def desc
    "Adds output to wikitext"
  end


  #
  # The following methods are added here to keep the initialize method
  # readable
  #


  #
  # Extends Rex tables to be able to create Dokuwiki tables
  #
  def add_dokuwiki_to_rex
    Rex::Text::Table.class_eval do
      def to_dokuwiki
        str = prefix.dup
        # Print the header if there is one. Use headeri to determine wiki paragraph level
        if header
          level = "=" * headeri
          str << level + header + level + "\n"
        end
        # Add the column names to the top of the table
        columns.each do |col|
          str << "^ " + col.to_s + " "
        end
        str << "^\n" unless columns.count.eql? 0
        # Fill out the rest of the table with rows
        rows.each do |row|
          row.each do |val|
            cell = val.to_s
            cell = "<nowiki>#{cell}</nowiki>" if cell.include? "|"
            str << "| " + cell + " "
          end
          str << "|\n" unless rows.count.eql? 0
        end
        return str
      end
    end
  end

  #
  # Extends Rex tables to be able to create Mediawiki tables
  #
  def add_mediawiki_to_rex
    Rex::Text::Table.class_eval do
      def to_mediawiki
        str = prefix.dup
        # Print the header if there is one. Use headeri to determine wiki
        # headline level. Mediawiki does headlines a bit backwards so that
        # the header level isn't limited. This results in the need to 'flip'
        # the headline length to standardize it.
        if header
          if headeri <= 6
            level = "=" * (-headeri + 7)
            str << "#{level} #{header} #{level}"
           else
             str << "#{header}"
          end
          str << "\n"
        end
        # Setup the table with some standard formatting options
        str << "{|class=\"wikitable\"\n"
        # Output formated column names as the first row
        unless columns.count.eql? 0
          str << "!"
          str << columns.join("!!")
          str << "\n"
        end
        # Add the rows to the table
        unless rows.count.eql? 0
          rows.each do |row|
            str << "|-\n|"
            # Try and prevent formatting tags from causing problems
            bad = ['&','<','>','"',"'",'/']
            r = row.join("|| ")
            r.each_char do |c|
              if bad.include? c
                str << Rex::Text.html_encode(c)
              else
                str << c
              end
            end
            str << "\n"
          end
        end
        # Finish up the table
        str << "|}"
        return str
      end
    end
  end

protected
end
end
