# -*- coding: binary -*-
module Msf
class Post
module Hardware
module RFTransceiver

module RFTransceiver

  attr_accessor :index

  # Validates success of a function call
  # @param r [Hash] A hash in expected format { "success" => true }
  # @return [Boolean] if success is true or not, returns false if hash is wrong
  def return_success(r)
    return false unless r
    return false unless r.has_key?('success')
    return r['success']
  end

  # Checks to see if this module is a RF Transceiver module
  # @return [Boolean] true if client.rftransceiver is loaded
  def is_rf?
    return true if client.rftransceiver
    print_error("Not an RFTransceiver module")
    return false
  end

  # Returns a list of supported USB indexes by relay
  # @return [Array] Example: [ 0, 1 ]
  def get_supported_indexes
    return [] unless is_rf?
    r = client.rftransceiver.supported_idx
    return r['indexes'] if r.has_key?('indexes')
    print_error("Invalid response from relay")
    return []
  end

  #
  # Sets the target USB index
  # @param idx [Integer]
  def set_index(idx)
    self.index = idx
  end

  #
  # Sets the frequency
  # @param freq [Integer] Example: 433000000
  # @param mhz [Integer] Optional Mhz
  # @return [Boolean] success value
  def set_freq(freq, mhz=-1)
    return false unless is_rf?
    self.index ||= 0
    opts = {}
    opts['mhz'] = mhz unless mhz == -1
    r = client.rftransceiver.set_freq(self.index, freq, opts)
    return_success(r)
  end

  #
  # Sets the mode TX, RX or Idle
  # @param mode [String] Mode type TX/RX/IDLE
  # @return [Boolean] success value
  def set_mode(mode)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_mode(self.index, mode)
    return_success(r)
  end

  #
  # Gets supported modulations
  # @return [Array] String list of modulations
  def get_modulations
    return [] unless is_rf?
    self.index ||= 0
    return client.rftransceiver.get_supported_modulations(self.index)
  end

  #
  # Sets the modulation
  # @param mod [String] Example ASK/OOK
  # @return [Boolean] success value
  def set_modulation(mod)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_modulation(self.index, mod)
    return_success(r)
  end

  #
  # Sets packet's fixed length
  # @param len [Integer] Length of packet
  # @return [Boolean] success value
  def set_flen(len)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.make_pkt_flen(self.index, len)
    return_success(r)
  end

  #
  # Sets packet's variable length
  # @param len [Integer] Length of packet
  # @return [Boolean] success value
  def set_vlen(len)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.make_pkt_vlen(self.index, len)
    return_success(r)
  end

  #
  # Transmits a RF Packet.  All data is base64 encoded before transmition to relay
  # @param data [String] Blog of data stored in a string.  Could be binary
  # @param repeat [Integer] Optional Repeat transmission
  # @param offset [Integer] Optional Offset within data section
  # @return [Boolean] success value
  def rfxmit(data, repeat=-1, offset=-1)
    return false unless is_rf?
    self.index ||= 0
    opts = {}
    opts['repeat'] = repeat unless repeat == -1
    opts['offset'] = offset unless offset == -1
    r = client.rftransceiver.rfxmit(self.index, data, opts)
    return_success(r)
  end

  #
  # Receive a packet
  # @param timeout [Integer] Optional timeout value
  # @param blocksize [Integer] Optional blocksize
  # @return [String] Base64 decoded data, could be binary
  def rfrecv(timeout = -1, blocksize = -1)
    return '' unless is_rf?
    self.index ||= 0
    opts = {}
    opts['timeout'] = timeout unless timeout == -1
    opts['blocksize'] = blocksize unless blocksize == -1
    client.rftransceiver.rfrecv(self.index, opts)
  end

  #
  # Enable packet CRC
  # @return [Boolean] success value
  def enable_crc
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.enable_packet_crc(self.index)
    return_success(r)
  end

  #
  # Enable Manchester encoding
  # @return [Boolean] success value
  def enable_manchester
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.enable_manchester(self.index)
    return_success(r)
  end

  #
  # Sets the channel
  # @param channel [Integer] Channel number
  # @return [Boolean] success value
  def set_channel(channel)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_channel(self.index, channel)
    return_success(r)
  end

  #
  # Sets the channel bandwidth
  # @param bandwidth [Integer] Bandwidth value
  # @param mhz [Integer] Mhz
  # @return [Boolean] success value
  def set_channel_bw(bandwidth, mhz=-1)
    return false unless is_rf?
    self.index ||= 0
    opts = {}
    opts['mhz'] = mhz unless mhz == -1
    r = client.rftransceiver.set_channel_bandwidth(self.index, bandwidth, opts)
    return_success(r)
  end

  #
  # Calculates the appropriate exponent and mantissa and updates the correct registers
  # chanspc is in kHz.  if you prefer, you may set the chanspc_m and chanspc_e settings directly.
  # only use one or the other:
  #      * chanspc
  #      * chanspc_m and chanspc_e
  # @param chanspc [Integer]
  # @param chanspc_m [Integer]
  # @param chanspc_e [Integer]
  # @param mhz [Integer] Mhz
  # @return [Boolean] success value
  def set_channel_spc(chanspc = -1, chanspc_m = -1, chanspc_e = -1, mhz=-1)
    return false unless is_rf?
    self.index ||= 0
    opts = {}
    opts['chanspc'] = chanspc unless chanspc == -1
    opts['chanspc_m'] = chanspc_m unless chanspc_m == -1
    opts['chanspc_e'] = chanspc_e unless chanspc_e == -1
    opts['mhz'] = mhz unless mhz == -1
    r = client.rftransceiver.set_channel_spc(self.index, opts)
    return_success(r)
  end

  #
  # Sets the baud rate
  # @param baud [Integer] baud rate
  # @param mhz [Integer] Optional Mhz
  # @return [Boolean] success value
  def set_baud(baud, mhz=-1)
    return false unless is_rf?
    self.index ||= 0
    opts = {}
    opts['mhz'] = mhz unless mhz == -1
    r = client.rftransceiver.set_baud_rate(self.index, baud, opts)
    return_success(r)
  end

  #
  # Sets the deviation
  # @param deviat [Integer] deviat value
  # @param mhz [Integer] Optional mhz
  # @return [Boolean] success value
  def set_deviation(deviat, mhz=-1)
    return false unless is_rf?
    self.index ||= 0
    opts = {}
    opts['mhz'] = mhz unless mhz == -1
    r = client.rftransceiver.set_deviation(self.index, deviat, opts)
    return_success(r)
  end

  #
  # Sets sync word
  # @param word [Integer] Sync word
  # @return [Boolean] success value
  def set_sync_word(word)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_sync_word(self.index, word)
    return_success(r)
  end

  #
  # Sets the sync mode
  # @param mode [Integer] Mode
  # @return [Boolean] success value
  def set_sync_mode(mode)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_sync_mode(self.index, mode)
    return_success(r)
  end

  #
  # Sets the number of preamble bits
  # @param bits [Integer] number of preamble bits to use
  # @return [Boolean] success value
  def set_preamble(bits)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_number_preamble(self.index, bits)
    return_success(r)
  end

  #
  # Sets the power to max.  Ensure you set the frequency first before using this
  # @return [Boolean] success value
  def max_power
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_maxpower(self.index)
    return_success(r)
  end

  #
  # Sets lowball.  Ensure you set the frequency first before using this
  # @return [Boolean] success value
  def set_lowball
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_lowball(self.index)
    return_success(r)
  end

  #
  # Set power level
  # @param level [Integer] Power level
  # @return [Boolean] success value
  def set_power(level)
    return false unless is_rf?
    self.index ||= 0
    r = client.rftransceiver.set_power(self.index, level)
    return_success(r)
  end
end

end
end
end
end

