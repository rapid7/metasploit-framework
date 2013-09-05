##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Finger Service User Enumerator',
      'Description' => 'Identify valid users through the finger service using a variety of tricks',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(79),
      OptString.new('USERS_FILE',
        [ true, 'The file that contains a list of default UNIX accounts.',
          File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
        ]
      )], self.class)
  end

  def run_host(ip)
    @users = {}

    begin
      vprint_status "#{rhost}:#{rport} - Sending empty finger request."
      finger_empty
      vprint_status "#{rhost}:#{rport} - Sending test finger requests."
      finger_zero
      finger_dot
      finger_chars
      vprint_status "#{rhost}:#{rport} - Sending finger request for user list: #{finger_user_common.join(", ")}"
      finger_list

    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      print_error("#{e} #{e.backtrace}")
    end
    report_service(:host => rhost, :port => rport, :name => "finger")

    if(@users.empty?)
      print_status("#{ip}:#{rport} No users found.")
    else
      print_good("#{ip}:#{rport} Users found: #{@users.keys.sort.join(", ")}")
      report_note(
        :host => rhost,
        :port => rport,
        :type => 'finger.users',
        :data => {:users => @users.keys}
      )
    end
  end


  def finger_empty
    connect
    sock.put("\r\n")
    buff = finger_slurp_data
    parse_users(buff)
    disconnect
  end

  def finger_zero
    connect
    sock.put("0\r\n")
    buff = finger_slurp_data
    parse_users(buff)
    disconnect
  end

  def finger_dot
    connect
    sock.put(".\r\n")
    buff = finger_slurp_data
    parse_users(buff)
    disconnect
  end

  def finger_chars
    connect
    sock.put("m m m m m m m m\r\n")
    buff = finger_slurp_data
    if buff.scan(/\r?\nm\s/).size > 7
      @multiple_requests = true
      vprint_status "#{rhost}:#{rport} - Multiple users per request is okay."
    end
    parse_users(buff)
    disconnect
  end

  def finger_list
    if !@multiple_requests
      finger_user_common.each do |user|
        next if @users[user]
        connect
        vprint_status "#{rhost}:#{rport} - Sending finger request for #{user}..."
        sock.put("#{user}\r\n")
        buff = finger_slurp_data
        ret = parse_users(buff)
        disconnect
        break if not ret
      end
    else
      while !finger_user_common.empty?
        user_batch = []
        while user_batch.size < 8 and !finger_user_common.empty?
          new_user = finger_user_common.shift
          next if @users.keys.include? new_user
          user_batch << new_user
        end
        connect
        vprint_status "#{rhost}:#{rport} - Sending finger request for #{user_batch.join(", ")}..."
        sock.put("#{user_batch.join(" ")}\r\n")
        buff = finger_slurp_data
        ret = parse_users(buff)
        disconnect
        break if not ret
      end
    end
  end

  def finger_slurp_data
    buff = ""
    begin
      while(res = sock.get_once(-1, 5) || '')
        buff << res
        break if buff.length > (1024*1024)
      end
    rescue ::Interrupt
      raise $!
    rescue ::Exception
    end
    buff
  end

  def finger_user_common
    if(! @common)
      File.open(datastore['USERS_FILE'], "rb") do |fd|
        data = fd.read(fd.stat.size)
        @common = data.split(/\n/).compact.uniq
        @common.delete("")
      end
    end
    @common
  end

  def parse_users(buff)
    buff.each_line do |line|
      uid = nil
      next if line.strip.empty?

      # Ignore Cisco systems
      return if line =~ /Line.*User.*Host.*Location/

      next if line =~ /user not found/i
      next if line =~ /no such user/i
      next if line =~ /must provide username/
      next if line =~ /real life: \?\?\?/
      next if line =~ /No one logged on/
      next if line =~ /^Login\s+Name\s+TTY/

      # print_status(">> #{line}")

      # No such file or directory == valid user bad utmp

      # Solaris
      if(line =~ /^([a-z0-9\.\_]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)/)
        uid = $1
        if ($2 != "Name")
          @users[uid] ||= {}
        end
      end

      # IRIX
      if(line =~ /^\s*Login name:\s*([^\s]+)\s+/i)
        uid = $1
        @users[uid] ||= {} if uid
      end

      # Debian GNU/Linux
      if(line =~ /^\s*Username:\s*([^\s]+)\s+/i)
        uid = $1
        @users[uid] ||= {} if uid
      end

      if uid
        print_good "#{rhost}:#{rport} - Found user: #{uid}" unless @users[uid] == :reported
        @users[uid] = :reported
        next
      end
    end
    return true
  end

end
