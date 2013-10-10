# -*- coding: binary -*-
module Msf

require 'msf/core/exploit/tcp'

###
#
# This module exposes methods that may be useful to exploits that deal with
# servers that speak the POP2 protocol.
#
###
module Exploit::Remote::Pop2

  include Exploit::Remote::Tcp

  #
  # Creates an instance of an POP2 exploit module.
  #
  def initialize(info = {})
    super

    # Register the options that all POP2 exploits may make use of.
    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(109),
        OptString.new('POP2USER', [ false, 'The username to authenticate as']),
        OptString.new('POP2PASS', [ false, 'The password for the specified username'])
      ], Msf::Exploit::Remote::Pop2)
  end

  #
  # This method establishes a POP2 connection to host and port specified by
  # the RHOST and RPORT options, respectively.  After connecting, the banner
  # message is read in and stored in the 'banner' attribute.
  #
  def connect(global = true)
    print_status("Connecting to POP2 server #{rhost}:#{rport}...")

    fd = super

    # Wait for a banner to arrive...
    self.banner = fd.get_once

    print_status("Connected to target POP2 server.")
    print_status("Banner: #{self.banner.split("\n")[0].strip}")

    # Return the file descriptor to the caller
    fd
  end

  #
  # Connect and login to the remote POP2 server using the credentials
  # that have been supplied in the exploit options.
  #
  def connect_login(global = true)
    pop2sock = connect(global)


    if !(user and pass)
      print_status("No username and password were supplied, unable to login")
      return false
    end

    print_status("Authenticating as #{user} with password #{pass}...")
    res = raw_send_recv("HELO #{user} #{pass}\r\n")

    if (res !~ /messages/)
      print_status("Authentication failed")
      return false
    end

    print_status("Messages: #{res}")
    return true
  end

  #
  # This method transmits a POP2 command and waits for a response.  If one is
  # received, it is returned to the caller.
  #
  def raw_send_recv(cmd, nsock = self.sock)
    nsock.put(cmd)
    res = nsock.get_once
  end

  #
  # This method sends one command with zero or more parameters
  #
  def send_cmd(args, recv = true, nsock = self.sock)
    cmd = args.join(" ") + "\r\n"
    if (recv)
      return raw_send_recv(cmd, nsock)
    else
      return raw_send(cmd, nsock)
    end
  end

  #
  # This method transmits a FTP command and does not wait for a response
  #
  def raw_send(cmd, nsock = self.sock)
    nsock.put(cmd)
  end

  ##
  #
  # Wrappers for getters
  #
  ##

  #
  # Returns the user string from the 'POP2USER' option.
  #
  def user
    datastore['POP2USER']
  end

  #
  # Returns the user string from the 'POP2PASS' option.
  #
  def pass
    datastore['POP2PASS']
  end

protected

  #
  # This attribute holds the banner that was read in after a successful call
  # to connect or connect_login.
  #
  attr_accessor :banner

end

end
