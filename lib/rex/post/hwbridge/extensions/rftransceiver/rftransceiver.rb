#
# -*- coding: binary -*-
require 'rex/post/hwbridge/client'

module Rex
module Post
module HWBridge
module Extensions
module RFTransceiver

###
# RF Transceiver extension - set of commands to be executed on transceivers like the TI cc11XX
###

class RFTransceiver < Extension

  def initialize(client)
    super(client, 'rftransceiver')

    # Alias the following things on the client object so that they
    # can be directly referenced
    client.register_extension_aliases(
      [
        {
          'name' => 'rftransceiver',
          'ext'  => self
        }
      ])
  end

  # Gets supported USB Indexes
  # @return [Array] Indexes
  def supported_idx
    client.send_request("/rftransceiver/supported_idx")
  end

  # Sets the frequency
  # @param idx [Integer] HW Index
  # @param opt [Hash] Optional: "mhz" => 24
  # @param freq [Integer] Frequency to set
  def set_freq(idx, freq, opt={})
    request = "/rftransceiver/#{idx}/set_freq?freq=#{freq}"
    request << "&mhz=#{opt['mhz']}" if opt.has_key? 'mhz'
    client.send_request(request)
  end

  # Retrieves a list of supported Modulations
  # @param idx [Integer] HW Index
  # @return [Array] of Modulation strings
  def get_supported_modulations(idx)
    client.send_request("/rftransceiver/#{idx}/get_modulations")
  end

  # Sets the mode
  # @param idx [Integer] HW Index
  # @param mode [String] Either RX, TX or IDLE
  def set_mode(idx, mode)
    client.send_request("/rftransceiver/#{idx}/set_mode?mode=#{mode}")
  end

  # Sets the modulation value
  # @param idx [Integer] HW Index
  # @param mod [String] Modulation Technique
  def set_modulation(idx, mod)
    client.send_request("/rftransceiver/#{idx}/set_modulation?mod=#{mod}")
  end

  # Sets fixed packet len
  # @param idx [Integer] HW Index
  # @param len [Integer] Length to set
  def make_pkt_flen(idx, len)
    client.send_request("/rftransceiver/#{idx}/make_packet_flen?len=#{len}")
  end

  # Sets variable packet len
  # @param idx [Integer] HW Index
  # @param len [Integer] Length to set
  def make_pkt_vlen(idx, len)
    client.send_request("/rftransceiver/#{idx}/make_packet_vlen?len=#{len}")
  end

  # Transmits data
  # @param idx [Integer] HW Index
  # @param data [String] Data to transmit
  # @param opt [Hash] Optional parameters: "repeat" => Integer, "offset" => Integer
  def rfxmit(idx, data, opt={})
    data = Base64.urlsafe_encode64(data)
    request = "/rftransceiver/#{idx}/rfxmit?data=#{data}"
    request << "&repeat=#{opt['repeat']}" if opt.has_key? 'repeat'
    request << "&offset=#{opt['offset']}" if opt.has_key? 'offset'
    client.send_request(request)
  end

  # Receives a packet
  # @param idx [Integer] HW Index
  # @param opt [Hash] Optional parameters: "timeout" => Integer, "blocksize" => Integer
  # @return [Hash] "data" => <recieved data> "timestamp" => When it was received
  def rfrecv(idx, opt={})
    request = "/rftransceiver/#{idx}/rfrecv"
    if opt.size() > 0
      first = true
      request << '?'
      if opt.has_key? 'timeout'
        request << "timeout=#{opt['timeout']}"
        first = false
      end
      if opt.has_key? 'blocksize'
        request << '&' unless first
        request << "blocksize=#{opt['blocksize']}"
      end
    end
    data = client.send_request(request)
    # Note the data is initially base64 encoded
    if data.size() > 0
      data['data'] = Base64.urlsafe_decode64(data['data']) if data.has_key? 'data'
    end
    data
  end

  def enable_packet_crc(idx)
    client.send_request("/rftransceiver/#{idx}/enable_packet_crc")
  end

  def enable_manchester(idx)
    client.send_request("/rftransceiver/#{idx}/enable_machester")
  end

  def set_channel(idx, channel)
    client.send_request("/rftransceiver/#{idx}/set_channel?channel=#{channel}")
  end

  def set_channel_bandwidth(idx, bandwidth, opt={})
    request = "/rftransceiver/#{idx}/set_channel_bandwidth?bw=#{bandwidth}"
    request << "&mhz=#{opt['mhz']}" if opt.has_key? 'mhz'
    client.send_request(request)
  end

  def set_channel_spc(idx, opt={})
    request = "/rftransceiver/#{idx}/set_channel_spc"
    if opt.size > 0
      request << '?'
      first = true
      if opt.has_key? 'chanspc'
        request << "chanspc=#{opt['chanspc']}"
        first = false
      end
      if opt.has_key? 'chanspc_m'
        request << '&' unless first
        request << "chanspc_m=#{opt['chanspc_m']}"
        first = false
      end
      if opt.has_key? 'chanspc_e'
        request << '&' unless first
        request << "chanspc_e=#{opt['chanspc_e']}"
        first = false
      end
      if opt.has_key? 'mhz'
        request << '&' unless first
        request << "mhz=#{opt['mhz']}"
      end
    end
    client.send_request(request)
  end

  def set_baud_rate(idx, rate, opt={})
    request = "/rftransceiver/#{idx}/set_baud_rate?rate=#{rate}"
    request << "&mhz=#{opt['mhz']}" if opt.has_key? 'mhz'
    client.send_request(request)
  end

  def set_deviation(idx, deviat, opt={})
    request = "/rftransceiver/#{idx}/set_deviation?deviat=#{deviat}"
    request << "&mhz=#{opt['mhz']}" if opt.has_key? 'mhz'
    client.send_request(request)
  end

  def set_sync_word(idx, word)
    client.send_request("/rftransceiver/#{idx}/set_sync_word?word=#{word}")
  end

  def set_sync_mode(idx, mode)
    client.send_request("/rftransceiver/#{idx}/set_sync_mode?mode=#{mode}")
  end

  def set_number_preamble(idx, num)
    client.send_request("/rftransceiver/#{idx}/set_number_preamble?num=#{num}")
  end

  def set_lowball(idx)
    client.send_request("/rftransceiver/#{idx}/set_lowball")
  end

  def set_maxpower(idx)
    client.send_request("/rftransceiver/#{idx}/set_maxpower")
  end

  def set_power(idx, power)
    client.send_request("/rftransceiver/#{idx}/set_power?power=#{power}")
  end
end

end
end
end
end
end

