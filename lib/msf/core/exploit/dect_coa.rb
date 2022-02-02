# -*- coding: binary -*-
module Msf

###
#
# This modules provides methods for interacting with a Com-On-Air DECT device
#
###

module Exploit::DECT_COA

  # Constants
  DECT_BAND_EMEA = 0x01
  DECT_BAND_US = 0x02
  DECT_BAND_BOTH = 0x03

  COA_MODE_IDLE = 0x0000
  COA_MODE_FP = 0x0100
  COA_MODE_PP = 0x0200
  COA_MODE_SNIFF = 0x0300
  COA_MODE_JAM = 0x0400
  COA_MODE_EEPROM = 0x0500

  COA_SUBMODE_SNIFF_SCANFP = 0x0001
  COA_SUBMODE_SNIFF_SCANPP = 0x0002
  COA_SUBMODE_SNIFF_SYNC = 0x0003

  COA_IOCTL_MODE = 0xD000
  COA_IOCTL_RADIO = 0xD001
  COA_IOCTL_RX = 0xD002
  COA_IOCTL_TX = 0xD003
  COA_IOCTL_CHAN = 0xD004
  COA_IOCTL_SLOT = 0xD005
  COA_IOCTL_RSSI = 0xD006
  COA_IOCTL_FIRMWARE = 0xD007
  COA_IOCTL_SETRFPI = 0xD008

  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('INTERFACE', [true, 'The name of the Com-On-Air Interface', '/dev/coa']),
        OptString.new('BAND', [true, 'DECT band', DECT_BAND_US]),
        OptString.new('CHAN', [false, 'DECT channel', 0]),
        OptString.new('RFPI', [false, 'RFPI for synchronous scan', nil])
      ], Msf::Exploit::DECT_COA
    )
  end

  def open_coa

    close_coa if self.dect_device

    begin
      self.dect_device = File.open(datastore['INTERFACE'], "wb+")
    rescue ::Exception => e
      print_error("Could not open the Com-On-Air device at #{datastore['INTERFACE']}")
      print_error("This module only works on Linux with the appropriate hardware and driver, while running as root")
      raise RuntimeError, "Could not open the Com-On-Air device: #{e}"
    end
  end

  def close_coa
    self.dect_device.close if self.dect_device
    self.dect_device = nil
  end


  def fp_scan_mode
    self.dect_device.ioctl(COA_IOCTL_MODE, [COA_MODE_SNIFF | COA_SUBMODE_SNIFF_SCANFP].pack('s'))
    set_band(datastore['BAND'])
  end

  def pp_scan_mode(rfpi)
    self.dect_device.ioctl(COA_IOCTL_MODE, [COA_MODE_SNIFF | COA_SUBMODE_SNIFF_SYNC].pack('S'))
    print_line("#{rfpi}")
    self.set_rfpi(rfpi.to_i)
  end

  def call_scan_mode
    self.dect_device.ioctl(COA_IOCTL_MODE, [COA_MODE_SNIFF | COA_SUBMODE_SNIFF_SCANPP].pack('s'))
    set_band(datastore['BAND'])
  end

  def stop_coa
    self.dect_device.ioctl(COA_IOCTL_MODE, [COA_MODE_IDLE].pack('s'))
  end

  def rfpi
    self.rfpi
  end

  def set_rfpi(rfpi)
    self.dect_device.ioctl(COA_IOCTL_SETRFPI, [rfpi].pack('s'))
  end

  def channel
    self.channel.to_i
  end

  def band
    self.band.to_i
  end

  def set_band(b)
    self.band = b.to_i

    if (band == DECT_BAND_US)
      set_channel(23)

    elsif (band == DECT_BAND_EMEA)
      set_channel(0)

    elsif (band == DECT_BAND_BOTH)
      set_channel(0)
    end
  end

  def set_channel(chan)
    self.channel = chan.to_i
    self.dect_device.ioctl(COA_IOCTL_CHAN, [channel].pack('i'))
  end

  def next_channel
    case band
    when DECT_BAND_US
      if (channel < 27)
        set_channel(channel + 1)
      else
        set_channel(23)
      end

    when DECT_BAND_EMEA
      if (channel < 9)
        set_channel(channel + 1)
      else
        set_channel(0)
      end

    when DECT_BAND_BOTH
      if (channel < 9)
        set_channel(channel + 1)
      elsif (channel == 9)
        set_channel(23)
      elsif (channel > 9 && channel < 27)
        set_channel(channel + 1)
      else
        set_channel(0)
      end
    end
  end

  def poll_coa
    data = ::IO.select([self.dect_device], nil, nil, 0.50)
    if (data != nil)
      data = data[0][0].read
    end

    data
  end

  def parse_rfpi(data)
    sprintf("%02x %02x %02x %02x %02x",data[0], data[1], data[2], data[3], data[4])
  end

  def parse_station(data)
    {
      'channel'  => data[0],
      'rssi'     => data[1],
      'rfpi_raw' => data[2,5],
      'rfpi'     => parse_rfpi(data[2,5])
    }
  end

  def parse_call(data)
    {
      'channel'  => data[0],
      'rssi'     => data[1],
      'rfpi_raw' => data[2,5],
      'rfpi'     => parse_rfpi(data[2,5])
    }
  end

  def record_coa(filename)
    raise RuntimeError, "DECT call recording is not supported yet"
    fd = File.open(filename, 'rb+')
    fd.close
  end

  attr_accessor :dect_device, :channel, :band
end
end

