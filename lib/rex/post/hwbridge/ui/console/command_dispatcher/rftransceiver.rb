# -*- coding: binary -*-
require 'rex/post/hwbridge'
require 'msf/core/auxiliary/report'

module Rex
module Post
module HWBridge
module Ui
###
# RF Transceiver extension - set of commands to be executed on transceivers like the TI cc11XX
###
class Console::CommandDispatcher::RFtransceiver
  include Console::CommandDispatcher
  include Msf::Auxiliary::Report

  #
  # List of supported commands.
  #
  def commands
    all = {
      'supported_idx'     => 'suppored USB indexes',
      'idx'               => 'sets an active idx',
      'freq'              => 'sets the frequency',
      'modulation'        => 'sets the modulation',
      'flen'              => 'sets the fixed length packet size',
      'vlen'              => 'sets the variable length packet size',
      'xmit'              => 'transmits some data',
      'recv'              => 'receive a packet of data',
      'enable_crc'        => 'enables crc',
      'enable_manchester' => 'enables manchester encoding',
      'channel'           => 'sets channel',
      'channel_bw'        => 'sets the channel bandwidth',
      'baud'              => 'sets the baud rate',
      'deviation'         => 'sets the deviation',
      'sync_word'         => 'sets the sync word',
      'preamble'          => 'sets the preamble number',
      'lowball'           => 'sets lowball',
      'power'             => 'sets the power level',
      'maxpower'          => 'sets max power'
    }

    all
  end

  def cmd_supported_idx
    indexes = client.rftransceiver.supported_idx
    if !indexes || !indexes.key?('indexes')
      print_line("error retrieving index list")
      return
    end
    indexes = indexes['indexes']
    unless indexes.size > 0
      print_line('none')
      return
    end
    self.idx = indexes[0].to_i if indexes.size.zero?
    str = "Supported Indexes: "
    str << indexes.join(', ')
    str << "\nUse idx to set your desired bus, default is 0"
    print_line(str)
  end

  #
  # Sets the USB IDS
  #
  def cmd_idx(*args)
    self.idx = 0
    idx_opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-i' => [ true, 'USB index, default 0' ]
    )
    idx_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: idx -i <Index number>\n")
        print_line(idx_opts.usage)
        return
      when '-i'
        self.idx = val
      end
    end
    print_line("set index to #{self.idx}")
  end

  def cmd_freq_help
    print_line("Sets the RF Frequency\n")
    print_line("Usage: freq -f <frequency number>")
    print_line("\nExample: freq -f 433000000")
  end

  #
  # Takes the results of a client request and prints Ok on success
  #
  def print_success(r)
    if r.key?('success') && r['success'] == true
      print_line("Ok")
    else
      print_line("Error")
    end
  end

  #
  # Sets the frequency
  #
  def cmd_freq(*args)
    self.idx ||= 0
    freq = -1
    mhz = nil
    arg = {}
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-f' => [ true, 'frequency to set, example: 433000000' ],
      '-m' => [ true, 'Mhz' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: freq -f <frequency number>\n")
        print_line(opts.usage)
        return
      when '-f'
        freq = val.to_i
      when '-m'
        mhz = val.to_i
      end
    end
    if freq == -1
      cmd_freq_help
      return
    end
    arg['mhz'] = mhz if mhz
    r = client.rftransceiver.set_freq(idx, freq, arg)
    print_success(r)
  end

  def cmd_modulation_help
    print_line("Usage: modulation -M <Modulation name>\n")
    print_line("Modulation names:\n")
    print_line("  #{client.rftransceiver.get_supported_modulations(idx)}")
    print_line("\nExample: modulation -M ASK/OOK")
  end

  #
  # Sets the modulation
  #
  def cmd_modulation(*args)
    self.idx ||= 0
    mod = nil
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-M' => [ true, 'Modulation name, See help for options' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        cmd_modulation_help
        print_line(opts.usage)
        return
      when '-M'
        mod = val
      end
    end
    unless mod
      cmd_modulation_help
      return
    end
    r = client.rftransceiver.set_modulation(idx, mod)
    print_success(r)
  end

  #
  # Sets the fixed length
  #
  def cmd_flen(*args)
    self.idx ||= 0
    flen = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-l' => [ true, 'Fixed Length' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: flen -l <length>\n")
        print_line(opts.usage)
        return
      when '-l'
        flen = val.to_i
      end
    end
    if flen == -1
      print_line("You must specify a length")
      return
    end
    r = client.rftransceiver.make_pkt_flen(idx, flen)
    print_success(r)
  end

  #
  # Sets the variable length
  #
  def cmd_vlen(*args)
    self.idx ||= 0
    vlen = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-l' => [ true, 'Variable Length' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: vlen -l <length>\n")
        print_line(opts.usage)
        return
      when '-l'
        vlen = val.to_i
      end
    end
    if vlen == -1
      print_line("You must specify a length")
      return
    end
    r = client.rftransceiver.make_pkt_vlen(idx, vlen)
    print_success(r)
  end

  #
  # Xmit packet
  #
  def cmd_xmit(*args)
    self.idx ||= 0
    data = nil
    repeat = -1
    offset = -1
    arg = {}
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-d' => [ true, 'Variable Length' ],
      '-r' => [ true, 'Repeat' ],
      '-o' => [ true, 'Data offset' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: xmit -d <data>\n")
        print_line(opts.usage)
        return
      when '-d'
        data = val
      when '-r'
        repeat = val.to_i
      when '-o'
        offset = val.to_i
      end
    end
    unless data
      print_line("You must specify the data argument (-d)")
      return
    end
    arg['repeat'] = repeat unless repeat == -1
    arg['offset'] = offset unless offset == -1
    r = client.rftransceiver.rfxmit(idx, data, arg)
    print_success(r)
  end

  #
  # Recieve data packet
  #
  def cmd_recv(*args)
    self.idx ||= 0
    arg = {}
    timeout = -1
    blocksize = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-t' => [ true, 'timeout' ],
      '-b' => [ true, 'blocksize' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: recv\n")
        print_line(opts.usage)
        return
      when '-t'
        timeout = val.to_i
      when '-b'
        blocksize = val.to_i
      end
    end
    arg['blocksize'] = blocksize unless blocksize == -1
    arg['timeout'] = timeout unless timeout == -1
    r = client.rftransceiver.rfrecv(idx, arg)
    if r.key?('data') && r.key?('timestamp')
      print_line(" #{r['timestamp']}: #{r['data'].inspect}")
    else
      print_line("Error")
    end
  end

  #
  # Enable CRC
  #
  def cmd_enable_crc(*args)
    self.idx ||= 0
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ]
    )
    opts.parse(args) do |opt, _idx, _val|
      case opt
      when '-h'
        print_line("Usage: enable_crc\n")
        print_line(opts.usage)
        return
      end
    end
    r = client.rftransceiver.enable_packet_crc(idx)
    print_success(r)
  end

  #
  # Enable Manchester encoding
  #
  def cmd_enable_manchester(*args)
    self.idx ||= 0
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: enable_manchester\n")
        print_line(opts.usage)
        return
      end
    end
    r = client.rftransceiver.enable_manchester(idx)
    print_success(r)
  end

  #
  # Set channel
  #
  def cmd_channel(*args)
    self.idx ||= 0
    channel = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-c' => [ true, 'Channel number' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: channel -c <channel number>\n")
        print_line(opts.usage)
        return
      when '-c'
        channel = val.to_i
      end
    end
    if channel == -1
      print_line("You must specify a channel number")
      return
    end
    r = client.rftransceiver.set_channel(idx, channel)
    print_success(r)
  end

  #
  # Set channel bandwidth
  #
  def cmd_channel_bw(*args)
    self.idx ||= 0
    bandwidth = -1
    mhz = nil
    arg = {}
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Bandwidth' ],
      '-m' => [ true, 'Mhz' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: channel_bw -b <bandwidth>\n")
        print_line(opts.usage)
        return
      when '-b'
        bandwidth = val.to_i
      when '-m'
        mhz = val.to_i
      end
    end
    if bandwidth == -1
      print_line("You must specify the bandwidth (-b)")
      return
    end
    arg['mhz'] = mhz if mhz
    r = client.rftransceiver.set_channel_bandwidth(idx, bandwidth, arg)
    print_success(r)
  end

  #
  # Set baud rate
  #
  def cmd_baud(*args)
    self.idx ||= 0
    baud = -1
    mhz = nil
    arg = {}
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-b' => [ true, 'Baud rate' ],
      '-m' => [ true, 'Mhz' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: baud -b <baud rate>\n")
        print_line(opts.usage)
        return
      when '-b'
        baud = val.to_i
      when '-m'
        mhz = val.to_i
      end
    end
    if baud == -1
      print_line("You must specify a baud rate")
      return
    end
    arg['mhz'] = mhz if mhz
    r = client.rftransceiver.set_baud_rate(idx, baud, arg)
    print_success(r)
  end

  #
  # Set Deviation
  #
  def cmd_deviation(*args)
    self.idx ||= 0
    deviat = -1
    mhz = nil
    arg = {}
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-d' => [ true, 'Deviat' ],
      '-m' => [ true, 'Mhz' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: deviation -d <deviat value>\n")
        print_line(opts.usage)
        return
      when '-d'
        deviat = val.to_i
      when '-m'
        mhz = val.to_i
      end
    end
    if deviat == -1
      print_line("You must specify a deviat value")
      return
    end
    arg['mhz'] = mhz if mhz
    r = client.rftransceiver.set_deviation(idx, deviat, arg)
    print_success(r)
  end

  #
  # Set Sync word
  #
  def cmd_sync_word(*args)
    self.idx ||= 0
    word = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-w' => [ true, 'Sync word (Integer)' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: sync_word -w <int>\n")
        print_line(opts.usage)
        return
      when '-w'
        word = val.to_i
      end
    end
    if word == -1
      print_line("You must specify a sync word")
      return
    end
    r = client.rftransceiver.set_sync_word(idx, word)
    print_success(r)
  end

  def cmd_preamble_help
    print_line("get the minimum number of preamble bits to be transmitted. note this is a flag, not a count")
    print_line("so the return value must be interpeted - e.g. 0x30 == 0x03 << 4 == MFMCFG1_NUM_PREAMBLE_6 == 6 bytes")
  end

  #
  # Set Preamble size
  #
  def cmd_preamble(*args)
    self.idx ||= 0
    preamble = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-n' => [ true, 'Number of preamble' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: preamble -n <number bits>\n")
        print_line(opts.usage)
        return
      when '-n'
        preamble = val.to_i
      end
    end
    if preamble == -1
      print_line("You must specify the number of preamble bits")
      return
    end
    r = client.rftransceiver.set_number_preamble(idx, preamble)
    print_success(r)
  end

  def cmd_lowball_help
    print_line("Lowball is frequency dependent.  Set frequency first")
  end

  def cmd_lowball(*args)
    self.idx ||= 0
    if args.length > 0
      cmd_lowball_help
      return
    end
    r = client.rftransceiver.set_lowball(idx)
    print_success(r)
  end

  def cmd_maxpower_help
    print_line("Max power is frequency dependent.  Set frequency first")
  end

  #
  # Sets max power
  #
  def cmd_maxpower(*args)
    self.idx ||= 0
    if args.length > 0
      cmd_maxpower_help
      return
    end
    r = client.rftransceiver.set_maxpower(idx)
    print_success(r)
  end

  def cmd_power(*args)
    self.idx ||= 0
    power = -1
    opts = Rex::Parser::Arguments.new(
      '-h' => [ false, 'Help Banner' ],
      '-p' => [ true, 'Power level' ]
    )
    opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line("Usage: power -p <power level>\n")
        print_line(opts.usage)
        return
      when '-p'
        power = val.to_i
      end
    end
    if power == -1
      print_line("You must specify the power level")
      return
    end
    r = client.rftransceiver.set_power(idx, power)
    print_success(r)
  end

  #
  # Name for this dispatcher
  #
  def name
    'RFtransceiver'
  end

  attr_accessor :idx
end

end
end
end
end

