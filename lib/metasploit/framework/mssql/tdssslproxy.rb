# -*- coding: binary -*-

require 'openssl'

#
# TDSSSLProxy:
#
# SQL Server uses the TDS protocol to transmit data between clients and
# servers. Of course this sits on top of TCP.
#
# By default, the TDS payload is not encrypted. However, if "force
# encryption" is set under the SQL Server protocol properties, it will
# use SSL/TLS to encrypt the TDS data. Oddly, the entire TCP stream is
# not encrypted (as is say for HTTPS), but instead a TDS header is
# put on the front of the TLS packet. As a result, the full TLS/SSL
# setup is done within a series of TDS payloads.
#
# This "proxy" basically creates a fake SSL endpoint (s2) from which it
# can add/remove the TDS header as required. This is implemented as a
# socket pair (think, a bidirectional pipe), where the other end is s1:
#
# sslsock <-> s1 <-> s2 <-> tdssock <-> target SQL Server.
#
# (tdssock is the reference to the "sock" from the scanner module)
#
# TO DO:
#
# This enables brute force of a SQL Server which requires encryption.
# However, future updates will permit any read/write using
# mssql_send_recv() to use crypto if required and transparently to
# other MSF developers.
#
# Cheers, JH

class TDSSSLProxy

  TYPE_TDS7_LOGIN = 16
  TYPE_PRE_LOGIN_MESSAGE = 18
  STATUS_END_OF_MESSAGE = 0x01

  def initialize(sock)
    @tdssock = sock
    @s1, @s2 = Rex::Socket.tcp_socket_pair
  end

  def cleanup
    @running = false
    @t1.join
  end

  def setup_ssl
    @running = true
    @t1 = Thread.start { ssl_setup_thread }
    ctx = OpenSSL::SSL::SSLContext.new(:SSLv23)
    ctx.ciphers = "ALL:!ADH:!EXPORT:!SSLv2:!SSLv3:+HIGH:+MEDIUM"
    @ssl_socket = OpenSSL::SSL::SSLSocket.new(@s1, ctx)
    @ssl_socket.connect
  end

  def send_recv(pkt)
    @ssl_socket.write(pkt)
    done = false
    resp = ""

    while (not done)
      head = @ssl_socket.read(8)
      if !(head and head.length == 8)
        return false
      end

      # Is this the last buffer?
      if (head[1, 1] == "\x01" or not check_status)
        done = true
      end

      # Grab this block's length
      rlen = head[2, 2].unpack('n')[0] - 8

      while (rlen > 0)
        buff = @ssl_socket.read(rlen)
        return if not buff
        resp << buff
        rlen -= buff.length
      end

    end
    resp
  end

  def ssl_setup_thread
    while @running do
      res = select([@tdssock, @s2], nil, nil, 0.1)
      if res
        res[0].each do |r|
          # response from SQL Server for client
          if r == @tdssock
            resp = @tdssock.recv(4096)
            if @ssl_socket.state[0, 5] == "SSLOK"
              @s2.send(resp, 0)
            else
              @s2.send(resp[8..-1], 0)
            end
          end

          # request from client for SQL Server
          if r == @s2
            resp = @s2.recv(4096)
            # SSL negotiation completed - just send it on
            if @ssl_socket.state[0, 5] == "SSLOK"
              @tdssock.send(resp, 0)
              # Still doing SSL
            else
              tds_pkt_len = 8 + resp.length
              pkt_hdr = ''
              pkt_hdr << [TYPE_PRE_LOGIN_MESSAGE, STATUS_END_OF_MESSAGE, tds_pkt_len, 0x0000, 0x00, 0x00].pack('CCnnCC')
              pkt = pkt_hdr << resp
              @tdssock.send(pkt, 0)
            end
          end
        end
      end
    end
    @s1.close
    @s2.close
  end
end

