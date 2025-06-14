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
        'Name' => 'Modbus Client Utility',
        'Description' => %q{
          This module allows reading and writing data to a PLC using the Modbus protocol.
          This module is based on the 'modiconstop.rb' Basecamp module from DigitalBond,
          as well as the mbtget perl script.
        },
        'Author' => [
          'EsMnemon <esm[at]mnemonic.no>', # original write-only module
          'Arnaud SOULLIE  <arnaud.soullie[at]solucom.fr>', # code that allows read/write
          'Alexandrine TORRENTS <alexandrine.torrents[at]eurecom.fr>', # code that allows reading/writing at multiple consecutive addresses
          'Mathieu CHEVALIER <mathieu.chevalier[at]eurecom.fr>',
          'AZSG <AstroZombieSG@gmail.com>' # updated read actions to include function codes 2 and 4 and renamed actions to align with modbus standard 1.1b3
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['READ_COILS', { 'Description' => 'Read bits from several coils' } ], # Function Code 1 Read Coils
          ['READ_DISCRETE_INPUTS', { 'Description' => 'Read bits from several DISCRETE INPUTS' } ], # Function Code 2 Read Discrete Inputs
          ['READ_HOLDING_REGISTERS', { 'Description' => 'Read words from several HOLDING registers' } ], # Function Code 3 Read Holding Registers
          ['READ_INPUT_REGISTERS', { 'Description' => 'Read words from several INPUT registers' } ], # Function Code 4 Read Input Registers
          ['WRITE_COIL', { 'Description' => 'Write one bit to a coil' } ],
          ['WRITE_REGISTER', { 'Description' => 'Write one word to a register' } ],
          ['WRITE_COILS', { 'Description' => 'Write bits to several coils' } ],
          ['WRITE_REGISTERS', { 'Description' => 'Write words to several registers' } ],
          ['READ_ID', { 'Description' => 'Read device id' } ]
        ],
        'DefaultAction' => 'READ_HOLDING_REGISTERS'
      )
    )

    register_options(
      [
        Opt::RPORT(502),
        OptInt.new('DATA_ADDRESS', [true, 'Modbus data address']),
        OptInt.new('NUMBER', [false, 'Number of coils/registers to read (READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS modes only)', 1]),
        OptInt.new('DATA', [false, 'Data to write (WRITE_COIL and WRITE_REGISTER modes only)']),
        OptString.new('DATA_COILS', [false, 'Data in binary to write (WRITE_COILS mode only) e.g. 0110']),
        OptString.new('DATA_REGISTERS', [false, 'Words to write to each register separated with a comma (WRITE_REGISTERS mode only) e.g. 1,2,3,4']),
        OptInt.new('UNIT_NUMBER', [false, 'Modbus unit number', 1]),
        OptBool.new('HEXDUMP', [false, 'Print hex dump of response', false]),
      ]
    )
  end

  # a wrapper just to be sure we increment the counter
  def send_frame(payload)
    sock.put(payload)
    @modbus_counter += 1
    rsp = sock.get_once(-1, sock.def_read_timeout)
    dump_response(rsp)
    rsp
  end

  def dump_response(response)
    print_good('response: ' + response.unpack1('H*')) if datastore['HEXDUMP']
  end

  def make_payload(payload)
    packet_data = [@modbus_counter].pack('n')
    packet_data += "\x00\x00\x00" # dunno what these are
    packet_data += [payload.size].pack('c') # size byte
    packet_data += payload

    packet_data
  end

  def make_read_payload
    payload = [datastore['UNIT_NUMBER']].pack('c')
    payload += [@function_code].pack('c')
    payload += [datastore['DATA_ADDRESS']].pack('n')
    payload += [datastore['NUMBER']].pack('n')
    make_payload(payload)
  end

  def make_write_coil_payload(data)
    payload = [datastore['UNIT_NUMBER']].pack('c')
    payload += [@function_code].pack('c')
    payload += [datastore['DATA_ADDRESS']].pack('n')
    payload += [data].pack('c')
    payload += "\x00"

    packet_data = make_payload(payload)

    packet_data
  end

  def make_write_coils_payload(data, byte)
    payload = [datastore['UNIT_NUMBER']].pack('c')
    payload += [@function_code].pack('c')
    payload += [datastore['DATA_ADDRESS']].pack('n')
    payload += [datastore['DATA_COILS'].size].pack('n') # bit count
    payload += [byte].pack('c') # byte count
    for i in 0..(byte - 1)
      payload += [data[i]].pack('b*')
    end

    packet_data = make_payload(payload)

    packet_data
  end

  def make_write_register_payload(data)
    payload = [datastore['UNIT_NUMBER']].pack('c')
    payload += [@function_code].pack('c')
    payload += [datastore['DATA_ADDRESS']].pack('n')
    payload += [data].pack('n')

    make_payload(payload)
  end

  def make_write_registers_payload(data, size)
    payload = [datastore['UNIT_NUMBER']].pack('c')
    payload += [@function_code].pack('c')
    payload += [datastore['DATA_ADDRESS']].pack('n')
    payload += [size].pack('n') # word count
    payload += [2 * size].pack('c') # byte count
    for i in 0..(size - 1)
      payload += [data[i]].pack('n')
    end

    make_payload(payload)
  end

  def make_read_id_payload
    payload = [datastore['UNIT_NUMBER']].pack('c')
    payload += [@function_code].pack('c')
    payload += "\x0E\x01\x00" # dunno what these are
    make_payload(payload)
  end

  def handle_error(response)
    case response.reverse.unpack('c')[0].to_i
    when 1
      print_error('Error : ILLEGAL FUNCTION')
    when 2
      print_error('Error : ILLEGAL DATA ADDRESS')
    when 3
      print_error('Error : ILLEGAL DATA VALUE')
    when 4
      print_error('Error : SLAVE DEVICE FAILURE')
    when 6
      print_error('Error : SLAVE DEVICE BUSY')
    else
      print_error('Unknown error')
    end
    return
  end

  def read_coils
    if datastore['NUMBER'] + datastore['DATA_ADDRESS'] > 65535
      print_error('Coils addresses go from 0 to 65535. You cannot go beyond.')
      return
    end
    @function_code = 0x1
    print_status('Sending READ COILS...')
    response = send_frame(make_read_payload)
    values = []
    if response.nil?
      print_error('No answer for the READ COILS')
      return
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      loop = (datastore['NUMBER'] - 1) / 8
      for i in 0..loop
        bin_value = response[9 + i].unpack('b*')[0]
        list = bin_value.split('')
        for j in 0..7
          list[j] = list[j].to_i
          values[i * 8 + j] = list[j]
        end
      end
      values = values[0..(datastore['NUMBER'] - 1)]
      print_good("#{datastore['NUMBER']} coil values from address #{datastore['DATA_ADDRESS']} : ")
      print_good(values.to_s)
    else
      print_error('Unknown answer')
    end
  end

  def read_discrete_inputs
    if datastore['NUMBER'] + datastore['DATA_ADDRESS'] > 65535
      print_error('DISCRETE INPUT addresses go from 0 to 65535. You cannot go beyond.')
      return
    end
    @function_code = 0x2
    print_status('Sending READ DISCRETE INPUTS...')
    response = send_frame(make_read_payload)
    values = []
    if response.nil?
      print_error('No answer for the READ DISCRETE INPUTS')
      return
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      loop = (datastore['NUMBER'] - 1) / 8
      for i in 0..loop
        bin_value = response[9 + i].unpack('b*')[0]
        list = bin_value.split('')
        for j in 0..7
          list[j] = list[j].to_i
          values[i * 8 + j] = list[j]
        end
      end
      values = values[0..(datastore['NUMBER'] - 1)]
      print_good("#{datastore['NUMBER']} DISCRETE INPUT values from address #{datastore['DATA_ADDRESS']} : ")
      print_good(values.to_s)
    else
      print_error('Unknown answer')
    end
  end

  def read_holding_registers
    if datastore['NUMBER'] + datastore['DATA_ADDRESS'] > 65535
      print_error('Holding Registers addresses go from 0 to 65535. You cannot go beyond.')
      return
    end
    @function_code = 3
    print_status('Sending READ HOLDING REGISTERS...')
    response = send_frame(make_read_payload)
    values = []
    if response.nil?
      print_error('No answer for the READ HOLDING REGISTERS')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      for i in 0..(datastore['NUMBER'] - 1)
        values.push(response[9 + 2 * i..10 + 2 * i].unpack('n')[0])
      end
      print_good("#{datastore['NUMBER']} register values from address #{datastore['DATA_ADDRESS']} : ")
      print_good(values.to_s)
    else
      print_error('Unknown answer')
    end
  end

  def read_input_registers
    if datastore['NUMBER'] + datastore['DATA_ADDRESS'] > 65535
      print_error('Input Registers addresses go from 0 to 65535. You cannot go beyond.')
      return
    end
    @function_code = 4
    print_status('Sending READ INPUT REGISTERS...')
    response = send_frame(make_read_payload)
    values = []
    if response.nil?
      print_error('No answer for the READ INPUT REGISTERS')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      for i in 0..(datastore['NUMBER'] - 1)
        values.push(response[9 + 2 * i..10 + 2 * i].unpack('n')[0])
      end
      print_good("#{datastore['NUMBER']} register values from address #{datastore['DATA_ADDRESS']} : ")
      print_good(values.to_s)
    else
      print_error('Unknown answer')
    end
  end

  def write_coil
    @function_code = 5
    if datastore['DATA'] == 0
      data = 0
    elsif datastore['DATA'] == 1
      data = 255
    else
      print_error('Data value must be 0 or 1 in WRITE_COIL mode')
      return
    end
    print_status('Sending WRITE COIL...')
    response = send_frame(make_write_coil_payload(data))
    if response.nil?
      print_error('No answer for the WRITE COIL')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      print_good("Value #{datastore['DATA']} successfully written at coil address #{datastore['DATA_ADDRESS']}")
    else
      print_error('Unknown answer')
    end
  end

  def write_coils
    @function_code = 15
    temp = datastore['DATA_COILS']
    check = temp.split('')
    if temp.size > 65535
      print_error('DATA_COILS size must be between 0 and 65535')
      return
    end
    for j in check
      unless (j == '0') || (j == '1')
        print_error('DATA_COILS value must only contain 0s and 1s without space')
        return
      end
    end
    byte_number = (temp.size - 1) / 8 + 1
    data = []
    for i in 0..(byte_number - 1)
      data.push(temp[(i * 8 + 0)..(i * 8 + 7)])
    end
    print_status('Sending WRITE COILS...')
    response = send_frame(make_write_coils_payload(data, byte_number))
    if response.nil?
      print_error('No answer for the WRITE COILS')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      print_good("Values #{datastore['DATA_COILS']} successfully written from coil address #{datastore['DATA_ADDRESS']}")
    else
      print_error('Unknown answer')
    end
  end

  def write_register
    @function_code = 6
    if datastore['DATA'] < 0 || datastore['DATA'] > 65535
      print_error('Data to write must be an integer between 0 and 65535 in WRITE_REGISTER mode')
      return
    end
    print_status('Sending WRITE REGISTER...')
    response = send_frame(make_write_register_payload(datastore['DATA']))
    if response.nil?
      print_error('No answer for the WRITE REGISTER')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      print_good("Value #{datastore['DATA']} successfully written at registry address #{datastore['DATA_ADDRESS']}")
    else
      print_error('Unknown answer')
    end
  end

  def write_registers
    @function_code = 16
    check = datastore['DATA_REGISTERS'].split('')
    for j in 0..(check.size - 1)
      if (check[j] == '0') || (check[j] == '1') || (check[j] == '2') || (check[j] == '3') || (check[j] == '4') || (check[j] == '5') || (check[j] == '6') || (check[j] == '7') || (check[j] == '8') || (check[j] == '9') || (check[j] == ',')
        if (check[j] == ',') && (check[j + 1] == ',')
          print_error('DATA_REGISTERS cannot contain two consecutive commas')
          return
        end
      else
        print_error('DATA_REGISTERS value must only contain numbers and commas without space')
        return
      end
    end
    list = datastore['DATA_REGISTERS'].split(',')
    if list.size + datastore['DATA_ADDRESS'] > 65535
      print_error('Registers addresses go from 0 to 65535. You cannot go beyond.')
      return
    end
    data = []
    for i in 0..(list.size - 1)
      data[i] = list[i].to_i
    end
    for j in 0..(data.size - 1)
      if data[j] < 0 || data[j] > 65535
        print_error('Each word to write must be an integer between 0 and 65535 in WRITE_REGISTERS mode')
        return
      end
    end
    print_status('Sending WRITE REGISTERS...')
    response = send_frame(make_write_registers_payload(data, data.size))
    if response.nil?
      print_error('No answer for the WRITE REGISTERS')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack('C*')[7] == @function_code
      print_good("Values #{datastore['DATA_REGISTERS']} successfully written from registry address #{datastore['DATA_ADDRESS']}")
    else
      print_error('Unknown answer')
    end
  end

  def read_id
    @function_code = 0x2b
    obj_cnt = 0
    obj_id_pos = 0
    obj_len = 0
    print_status('Sending READ ID...')
    response = send_frame(make_read_id_payload)
    if response.nil?
      print_error('No answer for READ ID')
    elsif response.size < 9
      print_error('response is not modbus conform')
    elsif response.unpack('C*')[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.size < 16
      print_error('response is too short for READ ID')
    elsif response.unpack('C*')[7] == @function_code
      obj_cnt = response[13].unpack('C')[0]
      obj_id_pos = 14
      max_ref_size = response.size(-1)
      loop do
        obj_len = response[obj_id_pos + 1].unpack('C')[0]
        value = response.slice(obj_id_pos + 2, obj_len).unpack('a*')[0]
        obj_id = response[obj_id_pos].unpack('C')[0]
        print_good("Object ID #{obj_id}: #{value}")
        obj_cnt -= 1
        obj_id_pos = obj_id_pos + obj_len + 2
        if obj_id_pos > max_ref_size
          print_error('Out of bounds reference occurred whilst processing READ ID operation! Check sender data!')
          break
        end
        break unless obj_cnt > 0
      end
    else
      print_error('Unknown answer')
    end
  end

  def run
    @modbus_counter = 0x0000 # used for modbus frames
    connect
    case action.name
    when 'READ_COILS'
      read_coils
    when 'READ_DISCRETE_INPUTS'
      read_discrete_inputs
    when 'READ_HOLDING_REGISTERS'
      read_holding_registers
    when 'READ_INPUT_REGISTERS'
      read_input_registers
    when 'WRITE_COIL'
      write_coil
    when 'WRITE_REGISTER'
      write_register
    when 'WRITE_COILS'
      if datastore['DATA_COILS'].nil?
        print_error('The following option is needed in WRITE_COILS mode: DATA_COILS.')
        return
      else
        write_coils
      end
    when 'WRITE_REGISTERS'
      if datastore['DATA_REGISTERS'].nil?
        print_error('The following option is needed in WRITE_REGISTERS mode: DATA_REGISTERS.')
        return
      else
        write_registers
      end
    when 'READ_ID'
      read_id
    else
      print_error('Invalid ACTION')
    end
    disconnect
  end
end
