# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Zigbee

module Utils

  ## Constants for packet decoding fields
  # Frame Control Field
  DOT154_FCF_TYPE_MASK            = 0x0007  #: Frame type mask
  DOT154_FCF_SEC_EN               = 0x0008  #: Set for encrypted payload
  DOT154_FCF_FRAME_PND            = 0x0010  #: Frame pending
  DOT154_FCF_ACK_REQ              = 0x0020  #: ACK request
  DOT154_FCF_INTRA_PAN            = 0x0040  #: Intra-PAN activity
  DOT154_FCF_DADDR_MASK           = 0x0C00  #: Destination addressing mode mask
  DOT154_FCF_VERSION_MASK         = 0x3000  #: Frame version
  DOT154_FCF_SADDR_MASK           = 0xC000  #: Source addressing mask mode

  # Frame Control Field Bit Shifts
  DOT154_FCF_TYPE_MASK_SHIFT      = 0  #: Frame type mask mode shift
  DOT154_FCF_DADDR_MASK_SHIFT     = 10  #: Destination addressing mode mask
  DOT154_FCF_VERSION_MASK_SHIFT   = 12  #: Frame versions mask mode shift
  DOT154_FCF_SADDR_MASK_SHIFT     = 14  #: Source addressing mask mode shift

  # Address Mode Definitions
  DOT154_FCF_ADDR_NONE            = 0x0000  #: Not sure when this is used
  DOT154_FCF_ADDR_SHORT           = 0x0002  #: 4-byte addressing
  DOT154_FCF_ADDR_EXT             = 0x0003  #: 8-byte addressing

  DOT154_FCF_TYPE_BEACON          = 0     #: Beacon frame
  DOT154_FCF_TYPE_DATA            = 1     #: Data frame
  DOT154_FCF_TYPE_ACK             = 2     #: Acknowledgement frame
  DOT154_FCF_TYPE_MACCMD          = 3     #: MAC Command frame

  DOT154_CRYPT_NONE               = 0x00    #: No encryption, no MIC
  DOT154_CRYPT_MIC32              = 0x01    #: No encryption, 32-bit MIC
  DOT154_CRYPT_MIC64              = 0x02    #: No encryption, 64-bit MIC
  DOT154_CRYPT_MIC128             = 0x03    #: No encryption, 128-bit MIC
  DOT154_CRYPT_ENC                = 0x04    #: Encryption, no MIC
  DOT154_CRYPT_ENC_MIC32          = 0x05    #: Encryption, 32-bit MIC
  DOT154_CRYPT_ENC_MIC64          = 0x06    #: Encryption, 64-bit MIC
  DOT154_CRYPT_ENC_MIC128         = 0x07    #: Encryption, 128-bit MIC

  # Infer if the current session is for a ZigBee device.
  # @return [Boolean] true if session is for a ZigBee device, false otherwise
  def is_zigbee_hwbridge_session?
    return true if client.zigbee
    print_error("Not a ZigBee hwbridge session")
    false
  end

  # Verify if a device has been specified.
  # @return [Boolean] true if device is specified, false otherwise
  def verify_device(device)
    return true if device
    print_line("No target device set, use 'target' or specify bus via the options.")
    false
  end

  # Retrieves the target Zigbee device.  This is typically set by the user via the
  # interactive HWBridge command line
  # @return [String] Zigbee device ID
  def get_target_device
    return unless is_zigbee_hwbridge_session?
    return client.zigbee.get_target_device
  end

  # Sets the target default Zigbee Device.  This command typically isn't called via a script
  # Instead the user is expected to set this via the interactive HWBridge commandline
  # @param device [String] Zigbee device ID
  def set_target_device(device)
    return unless is_zigbee_hwbridge_session?
    client.zigbee.set_target_device device
  end

  # Sets the Zigbee Channel
  # @param device [String] Zigbee device ID
  # @param channel [Integer] Channel number, typically 11-25
  def set_channel(device, channel)
    return {} unless is_zigbee_hwbridge_session?
    device = client.zigbee.target_device unless device
    return {} unless verify_device(device)
    client.zigbee.set_channel(device, channel)
  end

  # Inject raw packets.  Need firmware on the zigbee device that supports transmission.
  # @param device [String] Zigbee device ID
  # @param data [String] Raw binary data sent as a string
  def inject(device, data)
    return {} unless is_zigbee_hwbridge_session?
    device = client.zigbee.target_device unless device
    return {} unless verify_device(device)
    client.zigbee.inject(device, data)
  end

  # Recieves data from the Zigbee device
  # @param device [String] Zigbee device ID
  # @return [String] Binary blob of returned data
  def recv(device)
    return {} unless is_zigbee_hwbridge_session?
    device = client.zigbee.target_device unless device
    return {} unless verify_device(device)
    client.zigbee.recv(device)
  end

  # Turn off Zigbee receiving
  # @param device [String] Zigbee device ID
  def sniffer_off(device)
    return {} unless is_zigbee_hwbridge_session?
    device = client.zigbee.target_device unless device
    return {} unless verify_device(device)
    client.zigbee.sniffer_off(device)
  end

  # Turn on Zigbee receiving
  # @param device [String] Zigbee device ID
  def sniffer_on(device)
    return {} unless is_zigbee_hwbridge_session?
    device = client.zigbee.target_device unless device
    return {} unless verify_device(device)
    client.zigbee.sniffer_on(device)
  end

  # Breaks up the packet into different sections.  Also provides
  # Some decoding information.  This method relates to Killerbee's Pktchop method and
  # Returns a similar array structure PktChop.  If it's a beacon data you will also have
  # A BEACONDATA array of raw beacon related packets.  You can pull other decoded portions from
  # the returned hash such as
  #  FSF
  #  SEQ
  #  SPAN_ID
  #  SOURCE
  #  SUPERFRAME
  #  GTS
  #  PENDING_ADDRESS_COUNT
  #  PROTOCOL_ID
  #  STACK_PROFILE
  #  CAPABILITY
  #  EXT_PAN_ID
  #  TX_OFFSET
  #  UPDATE_ID
  # @param packet [String] Raw data from recv
  # @return [Hash] { PktChop => [Array of data], ..
  def dot154_packet_decode(packet)
    result = {}
    offset = 0
    pktchop = ['', '', '', '', '', '', [], '']
    pktchop[0] = packet[0,2]
    # Sequence number
    pktchop[1] = packet[2]
    # Byte swap
    fcf = pktchop[0].reverse.unpack("H*")[0].hex
    result["FSF"] = fcf
    result["SEQ"] = pktchop[1]
    # Check if we are dealing with a beacon frame
    if (fcf & DOT154_FCF_TYPE_MASK) == DOT154_FCF_TYPE_BEACON
      beacondata = ["", "", "", "", "", "", "", "", "", ""]
      # 802.15.4 fields, SPAN and SA
      pktchop[4] = packet[3,2]
      pktchop[5] = packet[5,2]
      result["SPAN_ID"] = pktchop[4].reverse.unpack("H*")[0]
      result["SOURCE"] = pktchop[5].reverse.unpack("H*")[0]
      offset = 7

      # Superframe specification
      beacondata[0] = packet[offset,2]
      result["SUPERFRAME"] = beacondata[0]
      offset+=2

      # GTS data
      beacondata[1] = packet[offset]
      result["GTS"] = beacondata[1]
      offset+=1

      # Pending address count
      beacondata[2] = packet[offset]
      result["PENDING_ADDRESS_COUNT"] = beacondata[2]
      offset+=1

      # Protocol ID
      beacondata[3] = packet[offset]
      result["PROTOCOL_ID"] = beacondata[3]
      offset+=1

      # Stack Profile version
      beacondata[4] = packet[offset]
      result["STACK_PROFILE"] = beacondata[4]
      offset+=1

      # Capability information
      beacondata[5] = packet[offset]
      result["CAPABILITY"] = beacondata[5]
      offset+=1

      # Extended PAN ID
      beacondata[6] = packet[offset,8]
      result["EXT_PAN_ID"] = beacondata[6].reverse.unpack("H*")[0]
      offset+=8

      # TX Offset
      beacondata[7] = packet[offset,3]
      result["TX_OFFSET"] = beacondata[7]
      offset+=3

      # Update ID
      beacondata[8] = packet[offset]
      result["UPDATE_ID"] = beacondata[8]
      offset+=1
      pktchop[6] = beacondata
      result["BEACONDATA"] = beacondata
    else
      # Not a beacon frame

      # DPAN
      pktchop[2] = packet[3,2]
      offset = 5

      # Examine the destination addressing mode
      daddr_mask = (fcf & DOT154_FCF_DADDR_MASK) >> 10
      if daddr_mask == DOT154_FCF_ADDR_EXT
        pktchop[3] = packet[offset,8]
        offset += 8
      elsif daddr_mask == DOT154_FCF_ADDR_SHORT
        pktchop[3] = packet[offset,2]
        offset += 2
      end

      # Examine the Intra-PAN flag
      if (fcf & DOT154_FCF_INTRA_PAN) == 0
        pktchop[4] = packet[offset,2]
        offset += 2
      end

      # Examine the source addressing mode
      saddr_mask = (fcf & DOT154_FCF_SADDR_MASK) >> 14
      if daddr_mask == DOT154_FCF_ADDR_EXT
        pktchop[5] = packet[offset,8]
        offset += 8
      elsif daddr_mask == DOT154_FCF_ADDR_SHORT
        pktchop[5] = packet[offset,2]
        offset += 2
      end
    end
    # Append remaining payload
    pktchop[7] = packet[offset,packet.size] if offset < packet.size
    result["PktChop"] = pktchop
    return result
  end
end

end
end
end
end
