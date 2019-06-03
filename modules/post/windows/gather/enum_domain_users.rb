##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/netapi'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::NetAPI
  include Msf::Post::Windows::Accounts

  def initialize(info={})
    super( update_info( info,
      'Name'	       => 'Windows Gather Enumerate Active Domain Users',
      'Description'  => %q{
          This module will enumerate computers included in the primary Domain and attempt
          to list all locations the targeted user has sessions on. If the HOST option is specified
          the module will target only that host. If the HOST is specified and USER is set to nil, all users
          logged into that host will be returned.'
        },
        'License'      => MSF_LICENSE,
        'Author'       => [
          'Etienne Stalmans <etienne[at]sensepost.com>',
          'Ben Campbell'
        ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
    ))
    register_options(
      [
        OptString.new('USER', [false, 'Target User for NetSessionEnum']),
        OptString.new('HOST', [false, 'Target a specific host']),
      ])
  end

  def run
    sessions = []
    user = datastore['USER']
    host = datastore['HOST']

    if host
      if user
        print_status("Attempting to identify #{user} on #{host}...")
      else
        print_status("Attempting to get all logged in users on #{host}...")
      end
      sessions = net_session_enum(host, user)
    elsif user
      # Domain must be NETBIOS style rather than DNS style
      domain = get_domain

      if domain.blank?
        fail_with(Failure::Unknown, "Machine is not part of a domain.")
      else
        domain = domain.split('.').first.upcase
        print_status("Using domain: #{domain}")
        print_status("Getting list of domain hosts...")
      end

      hosts = net_server_enum(SV_TYPE_ALL, domain)

      if hosts
        len = hosts.count
        print_status("#{len} host(s) found")

        hosts.each do |host|
          sessions << net_session_enum(host[:name], user)
        end
      end

      sessions.flatten!
    else
      fail_with(Failure::BadConfig, "Invalid options, either HOST or USER must be specified.")
    end

    if sessions.nil? or sessions.count == 0
      fail_with(Failure::Unknown, "No sessions found")
    else
      print_status("#{sessions.count} session(s) identified")

      sessions.each do |s|
        if s
          print_good("#{s[:username]} logged in at #{s[:hostname]} and has been idle for #{s[:idletime]} seconds")
        end
      end
    end
  end
end

