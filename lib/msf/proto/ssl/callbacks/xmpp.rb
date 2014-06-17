# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  def xmpp_connect_msg(hostname)
    # http://xmpp.org/extensions/xep-0035.html
    msg = "<stream:stream xmlns='jabber:client' "
    msg << "xmlns:stream='http://etherx.jabber.org/streams' "
    msg << "version='1.0' "
    msg << "to='#{hostname}'>"
  end

  def tls_xmpp
    sock.put(xmpp_connect_msg(xmpp_domain))
    res = sock.get(response_timeout)
    if res && res.include?('host-unknown')
      xmpp_host = res.match(/ from='([\w.]*)' /)
      if xmpp_host && xmpp_host[1]
        disconnect
        establish_connect
        vprint_status("#{peer} - Connecting with autodetected remote XMPP hostname: #{xmpp_host[1]}...")
        sock.put(xmpp_connect_msg(xmpp_host[1]))
        res = sock.get(response_timeout)
      end
    end
    if res.nil? || res.include?('stream:error') || res !~ /<starttls xmlns=['"]urn:ietf:params:xml:ns:xmpp-tls['"]/
      vprint_error("#{peer} - Jabber host unknown. Please try changing the XMPPDOMAIN option.") if res && res.include?('host-unknown')
      return nil
    end
    msg = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    sock.put(msg)
    res = sock.get(response_timeout)
    return nil if res.nil? || !res.include?('<proceed')
    res
  end
end
