# -*- coding: binary -*-
module Msf

###
#
# This module provides service-specific methods for the DCERPC exploit mixin
#
###
module Exploit::Remote::DCERPC_MGMT

  # Connect to remote management interface
  def dcerpc_mgmt_connect(dport=135)
    Rex::Socket::Tcp.create(
      'PeerHost'  => rhost,
      'PeerPort'  => dport,
      'Proxies'   => proxies,
      'Context'   =>
        {
          'Msf'        => framework,
          'MsfExploit' => self,
        }
    )
  end

  NDR = Rex::Encoder::NDR

  # List all interfaces registered with this remote management interface
  def dcerpc_mgmt_inq_if_ids(dport=135)
    res = []

    begin

      eps = dcerpc_mgmt_connect(dport)

      eph = dcerpc_handle('afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0', 'ncacn_ip_tcp', [dport])
      opt = { 'Msf' => framework, 'MsfExploit' => self }

      dce = Rex::Proto::DCERPC::Client.new(eph, eps, opt)

      dce.call(0, '')

      if (dce.last_response != nil and dce.last_response.stub_data != nil)
        buff = dce.last_response.stub_data

        retstat = buff[0,4].unpack('N')[0]
        ifcount = buff[4,4].unpack('V')[0]
        ifstats = buff[12, 4 * ifcount]
        iflists = buff[12 + (4 * ifcount), buff.length]

        ifidx = 0
        while(ifidx < ifcount * 20)
          intf = Rex::Proto::DCERPC::UUID.uuid_unpack(iflists[ifidx, 16])
          vers = iflists[ifidx + 16,4].unpack('vv').map{|c| c.to_s}.join('.')
          res << [intf, vers]
          ifidx += 20
        end
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Remote Management Interface Error: #{e}")
      res = nil
    end

    eps.close if eps

    res
  end


  def dcerpc_mgmt_inq_if_stats(dport=135)
    res = []

    begin

      eps = dcerpc_mgmt_connect(dport)

      eph = dcerpc_handle('afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0', 'ncacn_ip_tcp', [dport])
      opt = { 'Msf' => framework, 'MsfExploit' => self }

      dce = Rex::Proto::DCERPC::Client.new(eph, eps, opt)

      dce.call(1, NDR.long(1024) )

      if (dce.last_response != nil and dce.last_response.stub_data != nil)
        buff = dce.last_response.stub_data
        rcnt = buff[0,4].unpack('V')[0]
        0.upto(rcnt-1) do |s|
          res << buff[8 + (4*s), 4].unpack('V')[0]
        end
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Remote Management Interface Error: #{e}")
      res = nil
    end

    eps.close if eps

    res
  end

  def dcerpc_mgmt_is_server_listening(dport=135)
    res = nil

    begin

      eps = dcerpc_mgmt_connect(dport)

      eph = dcerpc_handle('afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0', 'ncacn_ip_tcp', [dport])
      opt = { 'Msf' => framework, 'MsfExploit' => self }

      dce = Rex::Proto::DCERPC::Client.new(eph, eps, opt)

      dce.call(2, '')

      if (dce.last_response != nil and dce.last_response.stub_data != nil)
        buff = dce.last_response.stub_data
        res  = buff[0,4].unpack('V')[0]
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Remote Management Interface Error: #{e}")
      res = nil
    end

    eps.close if eps

    res
  end

  def dcerpc_mgmt_stop_server_listening(dport=135)
    res = nil

    begin

      eps = dcerpc_mgmt_connect(dport)

      eph = dcerpc_handle('afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0', 'ncacn_ip_tcp', [dport])
      opt = { 'Msf' => framework, 'MsfExploit' => self }

      dce = Rex::Proto::DCERPC::Client.new(eph, eps, opt)

      dce.call(3, '')

      if (dce.last_response != nil and dce.last_response.stub_data != nil)
        buff = dce.last_response.stub_data
        res  = buff[0,4].unpack('V')[0]
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Remote Management Interface Error: #{e}")
      res = nil
    end

    eps.close if eps

    res
  end

  def dcerpc_mgmt_inq_princ_name(dport=135)
    res = nil

    begin

      eps = dcerpc_mgmt_connect(dport)

      eph = dcerpc_handle('afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0', 'ncacn_ip_tcp', [dport])
      opt = { 'Msf' => framework, 'MsfExploit' => self }

      dce = Rex::Proto::DCERPC::Client.new(eph, eps, opt)

      dce.call(4,
        NDR.long(2) +
        NDR.long(256)
      )

      if (dce.last_response != nil and dce.last_response.stub_data != nil)
        buff = dce.last_response.stub_data
        res  = buff
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Remote Management Interface Error: #{e}")
      res = nil
    end

    eps.close if eps

    res
  end


end
end

