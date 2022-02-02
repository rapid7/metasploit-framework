##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  Aliases = [
    'auxiliary/scanner/smtp/enum'
  ]

  def initialize
    super(
      'Name'        => 'SMTP User Enumeration Utility',
      'Description' => %q{
        The SMTP service has two internal commands that allow the enumeration
        of users: VRFY (confirming the names of valid users) and EXPN (which
        reveals the actual address of users aliases and lists of e-mail
        (mailing lists)). Through the implementation of these SMTP commands can
        reveal a list of valid users.
        },
      'References'  =>
      [
        ['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
        ['OSVDB', '12551'],
        ['CVE', '1999-0531']
      ],
        'Author'      =>
      [
        'Heyder Andrade <heyder[at]alligatorteam.org>',
        'nebulus'
      ],
        'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(25),
        OptString.new('USER_FILE',
          [
            true, 'The file that contains a list of probable users accounts.',
            File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
          ]),
        OptBool.new('UNIXONLY', [ true, 'Skip Microsoft bannered servers when testing unix users', true])
      ])

    deregister_options('MAILTO','MAILFROM')
  end

  def smtp_send(data=nil)
    begin
      result=''
      code=0
      sock.put("#{data}")
      result=sock.get_once
      result.chomp! if(result)
      code = result[0..2].to_i if result
      return result, code
    rescue Rex::ConnectionError, Errno::ECONNRESET, ::EOFError
      return result, code
    rescue ::Exception => e
      print_error("#{rhost}:#{rport} Error smtp_send: '#{e.class}' '#{e}'")
      return nil, 0
    end
  end

  def run_host(ip)
    users_found = {}
    result = nil # temp for storing result of SMTP request
    code = 0     # status code parsed from result
    vrfy = true  # if vrfy allowed
    expn = true  # if expn allowed
    rcpt = true  # if rcpt allowed and useful
    usernames = extract_words(datastore['USER_FILE'])

    cmd = 'HELO' + " " + "localhost" + "\r\n"
    connect
    result, code = smtp_send(cmd)

    if(not result)
      print_error("#{rhost}:#{rport} Connection but no data...skipping")
      return
    end
    banner.chomp! if (banner)
    if(banner =~ /microsoft/i and datastore['UNIXONLY'])
      print_status("#{rhost}:#{rport} Skipping microsoft (#{banner})")
      return
    elsif(banner)
      print_status("#{rhost}:#{rport} Banner: #{banner}")
    end

    domain = result.split()[1]
    domain = 'localhost' if(domain == '' or not domain or domain.downcase == 'hello')


    vprint_status("#{ip}:#{rport} Domain Name: #{domain}")

    result, code = smtp_send("VRFY root\r\n")
    vrfy = (code == 250)
    users_found = do_enum('VRFY', usernames) if (vrfy)

    if(users_found.empty?)
    # VRFY failed, lets try EXPN
      result, code = smtp_send("EXPN root\r\n")
      expn = (code == 250)
      users_found = do_enum('EXPN', usernames) if(expn)
    end

    if(users_found.empty?)
    # EXPN/VRFY failed, drop back to RCPT TO
      result, code = smtp_send("MAIL FROM: root\@#{domain}\r\n")
      if(code == 250)
        user = Rex::Text.rand_text_alpha(8)
        result, code = smtp_send("RCPT TO: #{user}\@#{domain}\r\n")
        if(code >= 250 and code <= 259)
          vprint_status("#{rhost}:#{rport} RCPT TO: Allowed for random user (#{user})...not reliable? #{code} '#{result}'")
          rcpt = false
        else
          smtp_send("RSET\r\n")
          users_found = do_rcpt_enum(domain, usernames)
        end
      else
        rcpt = false
      end
    end

    if(not vrfy and not expn and not rcpt)
      print_status("#{rhost}:#{rport} could not be enumerated (no EXPN, no VRFY, invalid RCPT)")
      return
    end
    finish_host(users_found)
    disconnect

    rescue Rex::ConnectionError, Errno::ECONNRESET, Rex::ConnectionTimeout, EOFError, Errno::ENOPROTOOPT
    rescue ::Exception => e
      print_error("Error: #{rhost}:#{rport} '#{e.class}' '#{e}'")
  end

  def finish_host(users_found)
    if users_found and not users_found.empty?
      print_good("#{rhost}:#{rport} Users found: #{users_found.sort.join(", ")}")
      report_note(
        :host => rhost,
        :port => rport,
        :type => 'smtp.users',
        :data => {:users =>  users_found.join(", ")}
      )
    end
  end

  def kiss_and_make_up(cmd)
    vprint_status("#{rhost}:#{rport} SMTP server annoyed...reconnecting and saying HELO again...")
    disconnect
    connect
    smtp_send("HELO localhost\r\n")
    result, code = smtp_send("#{cmd}")
    result.chomp!
    cmd.chomp!
    vprint_status("#{rhost}:#{rport} - SMTP - Re-trying #{cmd} received #{code} '#{result}'")
    return result,code
  end

  def do_enum(cmd, usernames)

    users = []
    usernames.each {|user|
      next if user.downcase == 'root'
      result, code = smtp_send("#{cmd} #{user}\r\n")
      vprint_status("#{rhost}:#{rport} - SMTP - Trying #{cmd} #{user} received #{code} '#{result}'")
      result, code = kiss_and_make_up("#{cmd} #{user}\r\n") if(code == 0 and result.to_s == '')
      if(code == 250)
        vprint_status("#{rhost}:#{rport} - Found user: #{user}")
        users.push(user)
      end
    }
    return users
  end

  def do_rcpt_enum(domain, usernames)
    users = []
    usernames.each {|user|
      next if user.downcase == 'root'
      vprint_status("#{rhost}:#{rport} - SMTP - Trying MAIL FROM: root\@#{domain} / RCPT TO: #{user}...")
      result, code = smtp_send("MAIL FROM: root\@#{domain}\r\n")
      result, code = kiss_and_make_up("MAIL FROM: root\@#{domain}\r\n") if(code == 0 and result.to_s == '')

      if(code == 250)
        result, code = smtp_send("RCPT TO: #{user}\@#{domain}\r\n")
        if(code == 0 and result.to_s == '')
          kiss_and_make_up("MAIL FROM: root\@#{domain}\r\n")
          result, code = smtp_send("RCPT TO: #{user}\@#{domain}\r\n")
        end

        if(code == 250)
          vprint_status("#{rhost}:#{rport} - Found user: #{user}")
          users.push(user)
        end
      else
        vprint_status("#{rhost}:#{rport} MAIL FROM: #{user} NOT allowed during brute...aborting ( '#{code}' '#{result}')")
        break
      end
      smtp_send("RSET\r\n")
    }
    return users
  end

  def extract_words(wordfile)
    return [] unless wordfile && File.readable?(wordfile)
    words = File.open(wordfile, "rb") {|f| f.read}
    save_array = words.split(/\r?\n/)
    return save_array
  end
end
