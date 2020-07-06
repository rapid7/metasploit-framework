##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Modbus Banner Grabbing',
      'Description' => %q{
        Banner grabbing for Modbus using Function Code 43 (Read Device
        Identification). Modbus is a data communications protocol originally
        published by Modicon (now Schneider Electric) in 1979 for use with its
        programmable logic controllers (PLCs).
      },
      'Author'      =>
      [
        'Juan Escobar <juan[at]]null-life.com>', # @itsecurityco
        'Ezequiel Fernandez' # @capitan_alfa
      ],
      'References'  =>
      [
        [ 'URL', 'https://en.wikipedia.org/wiki/Modbus#Modbus_TCP_frame_format_(primarily_used_on_Ethernet_networks)' ],
        [ 'URL', 'https://github.com/industrialarmy/Hello_Proto' ],
      ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(502),
        OptInt.new('UNIT_ID', [true, "Tells the Slave Address of the device behind the gateway [1..254]", 0]),
        OptInt.new('TIMEOUT', [true, 'Timeout for the network probe', 2])
      ])
  end

  # Main Modbus exception codes
  def handle_exception_codes(code)
    case code
      when "\xab\x01"
        print_error("Illegal Function: Function code received in the query is not recognized or allowed by slave.")
      when "\xab\x02"
        print_error("Illegal Data Address: Data address of some or all the required entities are not allowed or do not exist in slave.")
      when "\xab\x03"
        print_error("Illegal Data Value: Value is not accepted by slave.")
      when "\xab\x04"
        print_error("Slave Device Failure: Unrecoverable error occurred while slave was attempting to perform requested action.")
      when "\xab\x05"
        print_error("Acknowledge: Slave has accepted request and is processing it, but a long duration of time is required.")
      when "\xab\x06"
        print_error("Slave Device Busy: Slave is engaged in processing a long-duration command.")
      when "\xab\x07"
        print_error("Negative Acknowledge: Slave cannot perform the programming functions.")
      when "\xab\x08"
        print_error("Memory Parity Error: Slave detected a parity error in memory.")
      when "\xab\x0a"
        print_error(" Gateway Path Unavailable: Specialized for Modbus gateways. Indicates a misconfigured gateway.")
      when "\xab\x0b"
        print_error("Gateway Target Device Failed to Respond: Specialized for Modbus gateways.")
      else
        print_error("MODBUS - received incorrect data #{ data[mbtcp['func_code']['start'], 2].inspect }")
    end
  end

  def run_host(ip)
    object_name = {
      0   => "VendorName",
      1   => "ProductCode",
      2   => "Revision",
      3   => "VendorUrl",
      4   => "ProductName",
      5   => "ModelName",
      6   => "UserAppName",
      7   => "Reserved",
      8   => "Reserved",
      9   => "Reserved",
      10  => "Reserved",
      128 => "PrivateObjects",
      255 => "PrivateObjects"
    }

    # Modbus/TCP Response Bytes
    mbtcp = {
        'trans_id' =>         { 'start' =>  0, 'bytes' => 2 },
        'prot_id' =>          { 'start' =>  2, 'bytes' => 2 },
        'len' =>              { 'start' =>  4, 'bytes' => 2 },
        'unit_id' =>          { 'start' =>  6, 'bytes' => 1 },
        'func_code' =>        { 'start' =>  7, 'bytes' => 1 },
        'mei' =>              { 'start' =>  8, 'bytes' => 1 },
        'read_device_id' =>   { 'start' =>  9, 'bytes' => 1 },
        'conformity_level' => { 'start' => 10, 'bytes' => 1 },
        'more_follows' =>     { 'start' => 11, 'bytes' => 1 },
        'next_object_id' =>   { 'start' => 12, 'bytes' => 1 },
        'num_objects' =>      { 'start' => 13, 'bytes' => 1 },
        'object_id' =>        { 'start' => 14, 'bytes' => 1 },
        'objects_len' =>      { 'start' => 15, 'bytes' => 1 },
        'object_str_value' => { 'start' => 16, 'bytes' => nil }
    }

    begin
      connect()

      packet  = "\x44\x62" # Transaction Identifier
      packet << "\x00\x00" # Protocol Identifier
      packet << "\x00\x05" # Length
      packet << [datastore['UNIT_ID']].pack("C") # Unit Identifier
      packet << "\x2b"     # .010 1011 = Function Code: Encapsulated Interface Transport (43)
      packet << "\x0e"     # MEI type: Read Device Identification (14)
      packet << "\x03"     # Read Device ID: Extended Device Identification (3)
      packet << "\x00"     # Object ID: VendorName (0)

      sock.put(packet)
      data = sock.get_once(-1, datastore['TIMEOUT'])

      if data
        # Read Device Identification (43)
        if data[mbtcp['func_code']['start'], 2] == "\x2b\x0e"
          num_objects = data[mbtcp['num_objects']['start'], mbtcp['num_objects']['bytes']].unpack("C")[0]
          print_status("Number of Objects: #{ num_objects }")
          object_start = mbtcp['object_id']['start']

          for i in 1..num_objects.to_i
            object = Hash.new
            object['id']        = data[object_start, mbtcp['object_id']['bytes']].unpack("C")[0]
            object['len']       = data[object_start + mbtcp['object_id']['bytes'], mbtcp['objects_len']['bytes']].unpack("C")[0]
            object["str_value"] = data[object_start + mbtcp['object_id']['bytes'] + mbtcp['objects_len']['bytes'], object['len']].unpack("a*")[0]
            begin
              object['name'] = object_name[object['id']]
            rescue
              object['name'] = "Name X"
            end

            print_good("#{ object['name'] }: #{ object['str_value'] }")
            object_start = object_start + mbtcp['object_id']['bytes'] + mbtcp['objects_len']['bytes'] + object['len']

            report_note(
              :host => ip,
              :proto => 'tcp',
              :port => rport,
              :sname => 'modbus',
              :type => "modbus.#{ object['name'].downcase }",
              :data => object['str_value']
            )
          end
        else
          handle_exception_codes(data[mbtcp['func_code']['start'], 2])
        end
      else
        raise ::Rex::ConnectionTimeout
      end
    rescue ::Interrupt
      print_error("MODBUS - Interrupt during payload")
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionError, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused => e
      print_error("MODBUS - Network error during payload: #{e}")
      return nil
    rescue ::EOFError
      print_error("MODBUS - No reply")
    end

    def cleanup
      disconnect() rescue nil
    end
  end
end
