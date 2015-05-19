#
# $Id$
# $Revision$
#

module Msf

###
#
# This class hooks all sockets created by a running exploit
# and prevents data from being sent that matches a known IPS
# signature.
#
###

class Plugin::IPSFilter < Msf::Plugin

  ###
  #
  # This class implements a socket communication logger
  #
  ###
  class IPSSocketEventHandler
    include Rex::Socket::Comm::Events

    def on_before_socket_create(comm, param)
    end

    def on_socket_created(comm, sock, param)
      # Sockets created by the exploit have MsfExploit set and MsfPayload not set
      if (param.context['MsfExploit'] and (! param.context['MsfPayload'] ))
        sock.extend(IPSFilter::SocketTracer)
        sock.context = param.context
      end
    end
  end


  def initialize(framework, opts)
    super
    @ips_eh = IPSSocketEventHandler.new
    Rex::Socket::Comm::Local.register_event_handler(@ips_eh)
  end

  def cleanup
    Rex::Socket::Comm::Local.deregister_event_handler(@ips_eh)
  end

  def name
    "ips_filter"
  end

  def desc
    "Scans all outgoing data to see if it matches a known IPS signature"
  end

protected
end

end

# This module extends the captured socket instance
module IPSFilter
module SocketTracer

  attr_accessor :context

  # Hook the write method
  def write(buf, opts = {})
    if (ips_match(buf))
      print_error "Outbound write blocked due to possible signature match"
      return 0
    end
    super(buf, opts)
  end

  # Hook the read method
  def read(length = nil, opts = {})
    r = super(length, opts)
    if (ips_match(r))
      print_error "Incoming read may match a known signature"
    end
    return r
  end

  def close(*args)
    super(*args)
  end

  def ips_match(data)
    lp = localport
    rp = peerport

    SIGS.each do |s|
      begin
        r = Regexp.new(s[1])
        if (data.match(r))
          print_error "Matched IPS signature #{s[0]}"
          return true
        end
      rescue ::Exception => e
        print_error "Compiled error: #{s[1]}"
      end
    end

    return false
  end

  # Extend this as needed :-)
  SIGS =
  [
    ['DCOM.C', ".*\\\x5c\x00\\\x5c\x00\x46\x00\x58\x00\x4e\x00\x42\x00\x46\x00\x58\x00\x46\x00\x58\x00.*\xcc\xe0\xfd\x7f.*"],
    ['BLASTER', ".*\\\x5c\x00\\\x5c\x00\x46\x00\x58\x00\x4e\x00\x42\x00\x46\x00\x58\x00\x46\x00\x58\x00.*\xcc\xe0\xfd\x7f.*"],
    ['REMACT', ".*\xb8\x4a\x9f\x4d\x1c\\}\xcf\x11\x86\x1e\x00\x20\xaf\x6e.*"],
    ['x86 NOP SLED', "\x90\x90"],
  ]

end
end
