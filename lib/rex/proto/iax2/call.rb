# -*- coding: binary -*-
module Rex
module Proto
module IAX2
class Call

  attr_accessor :client
  attr_accessor :oseq, :iseq
  attr_accessor :scall, :dcall
  attr_accessor :codec, :state
  attr_accessor :ring_start, :ring_finish
  attr_accessor :itime
  attr_accessor :queue
  attr_accessor :audio_hook
  attr_accessor :audio_buff
  attr_accessor :time_limit
  attr_accessor :busy

  attr_accessor :caller_name
  attr_accessor :caller_number
  attr_accessor :dtmf


  def initialize(client, src_id)
    self.client = client
    self.scall  = src_id
    self.dcall  = 0
    self.iseq   = 0
    self.oseq   = 0
    self.state  = nil

    self.itime  = ::Time.now
    self.queue  = ::Queue.new

    self.audio_buff = []

    self.busy = false
    self.dtmf = ''
  end


  def dprint(msg)
    self.client.dprint(msg)
  end

  def wait_for(*stypes)
    begin
      ::Timeout.timeout( IAX_DEFAULT_TIMEOUT ) do
        while (res = self.queue.pop )
          if stypes.include?(res[1])
            return res
          end
        end
      end
    rescue ::Timeout::Error
      return nil
    end
  end

  # Register with the IAX endpoint
  def register
    self.client.send_regreq(self)
    res = wait_for( IAX_SUBTYPE_REGAUTH, IAX_SUBTYPE_REGREJ )
    return if not res

    if res[1] == IAX_SUBTYPE_REGREJ
      reason = res[2][IAX_IE_REGREJ_CAUSE] || "Unknown Reason"
      dprint("REGREJ: #{reason}")
      # Acknowledge the REGREJ
      self.client.send_ack(self)
      return
    end

    chall = nil
    if res[2][14] == "\x00\x03" and res[2][IAX_IE_CHALLENGE_DATA]
      self.dcall = res[0][0]
      chall = res[2][IAX_IE_CHALLENGE_DATA]
    end

    self.client.send_regreq_chall_response(self, chall)
    res = wait_for( IAX_SUBTYPE_REGACK, IAX_SUBTYPE_REGREJ )
    return if not res

    if res[1] == IAX_SUBTYPE_REGREJ
      reason = res[2][IAX_IE_REGREJ_CAUSE] || "Unknown Reason"
      dprint("REGREJ: #{reason}")
      return
    end

    if res[2][IAX_IE_APPARENT_ADDR]
      r_fam, r_port, r_addr = res[2][IAX_IE_APPARENT_ADDR].unpack('nnA4')
      r_addr = r_addr.unpack("C*").map{|x| x.to_s }.join(".")
      dprint("REGACK: Registered from address #{r_addr}:#{r_port}")
    end

    # Acknowledge the REGACK
    self.client.send_ack(self)

    self.state = :registered

    true
  end

  def dial(number)
    self.client.send_new(self, number)
    res = wait_for(IAX_SUBTYPE_AUTHREQ, IAX_SUBTYPE_ACCEPT)
    return if not res

    # Handle authentication if its requested
    if res[1] == IAX_SUBTYPE_AUTHREQ
      chall = nil
      if res[2][14] == "\x00\x03" and res[1][15]
        self.dcall = res[0][0]
        chall = res[2][15]
      end

      self.client.send_authrep_chall_response(self, chall)
      res = wait_for( IAX_SUBTYPE_ACCEPT)
      return if not res
    end

    self.codec = res[2][IAX_IE_DESIRED_CODEC].unpack("N")[0]
    self.state = :ringing
    self.ring_start = ::Time.now.to_i
    self.client.send_ack(self)
    true
  end

  def hangup
    self.client.send_hangup(self)
    self.state = :hangup
    true
  end

  def ring_time
    (self.ring_finish || Time.now).to_i - self.ring_start.to_i
  end

  def timestamp
    (( ::Time.now - self.itime) * 1000.0 ).to_i & 0xffffffff
  end

  def process_elements(data,off=0)
    res = {}
    while( off < data.length )
      ie_type = data[off    ,1].unpack("C")[0]
      ie_len  = data[off + 1,2].unpack("C")[0]
      res[ie_type] = data[off + 2, ie_len]
      off += ie_len + 2
    end
    res
  end

  # Handling incoming control packets
  # TODO: Enforce sequence order to prevent duplicates from breaking our state
  def handle_control(pkt)
    src_call, dst_call, tstamp, out_seq, inp_seq, itype = pkt.unpack('nnNCCC')

    # Scrub the high bits out of the call IDs
    src_call ^= 0x8000 if (src_call & 0x8000 != 0)
    dst_call ^= 0x8000 if (dst_call & 0x8000 != 0)

    phdr = [ src_call, dst_call, tstamp, out_seq, inp_seq, itype ]

    info  = nil
    stype = pkt[11,1].unpack("C")[0]
    info  = process_elements(pkt, 12) if [IAX_TYPE_IAX, IAX_TYPE_CONTROL].include?(itype)

    if dst_call != self.scall
      dprint("Incoming packet to inactive call: #{dst_call} vs #{self.scall}: #{phdr.inspect} #{stype.inspect} #{info.inspect}")
      return
    end

    # Increment the received sequence number
    self.iseq = (self.iseq + 1) & 0xff

    if self.state == :hangup
      dprint("Packet received after hangup, replying with invalid")
      self.client.send_invalid(self)
      return
    end

    # Technically these all require an ACK reply
    # NEW, HANGUP, REJECT, ACCEPT, PONG, AUTHREP, REGREL, REGACK, REGREJ, TXREL

    case itype
    when IAX_TYPE_DTMF_BEGIN
      self.dprint("DTMF BEG: #{pkt[11,1]}")
      self.dtmf << pkt[11,1]

    when IAX_TYPE_DTMF_END
      self.dprint("DTMF END: #{pkt[11,1]}")

    when IAX_TYPE_CONTROL
      case stype
      when IAX_CTRL_HANGUP
        dprint("HANGUP")
        self.client.send_ack(self)
        self.state = :hangup

      when IAX_CTRL_RINGING
        dprint("RINGING")
        self.client.send_ack(self)

      when IAX_CTRL_BUSY
        dprint("BUSY")
        self.busy  = true
        self.state = :hangup
        self.client.send_ack(self)

      when IAX_CTRL_ANSWER
        dprint("ANSWER")
        if self.state == :ringing
          self.state = :answered
          self.ring_finish = ::Time.now.to_i
        end
        self.client.send_ack(self)

      when IAX_CTRL_PROGRESS
        dprint("PROGRESS")

      when IAX_CTRL_PROCEED
        dprint("PROCEED")

      when 255
        dprint("STOP SOUNDS")
      end
      # Acknowledge all control packets
      # self.client.send_ack(self)

    when IAX_TYPE_IAX

      dprint( ["RECV", phdr, stype, info].inspect )
      case stype
      when IAX_SUBTYPE_HANGUP
        self.state = :hangup
        self.client.send_ack(self)
      when IAX_SUBTYPE_LAGRQ
        # Lagrps echo the timestamp
        self.client.send_lagrp(self, tstamp)
      when IAX_SUBTYPE_ACK
        # Nothing to do here
      when IAX_SUBTYPE_PING
        # Pongs echo the timestamp
        self.client.send_pong(self, tstamp)
      when IAX_SUBTYPE_PONG
        self.client.send_ack(self)
      else
        dprint( ["RECV-QUEUE", phdr, stype, info].inspect )
        self.queue.push( [phdr, stype, info ] )
      end

    when IAX_TYPE_VOICE
      v_codec = stype
      if self.state == :answered
        handle_audio(pkt)
      end
      self.client.send_ack(self)

    when nil
      dprint("Invalid control packet: #{pkt.unpack("H*")[0]}")
    end
  end


  # Encoded audio from the client
  def handle_audio(pkt)
    # Ignore audio received before the call is answered (ring ring)
    return if self.state != :answered

    # Extract the data from the packet (full or mini)
    data = audio_packet_data(pkt)

    # Decode the data into linear PCM frames
    buff = decode_audio_frame(data)

    # Call the caller-provided hook if its exists
    if self.audio_hook
      self.audio_buff(buff)
    # Otherwise append the frame to the buffer
    else
      self.audio_buff << buff
    end
  end

  def each_audio_frame(&block)
    self.audio_buff.each do |frame|
      block.call(frame)
    end
  end

  def decode_audio_frame(buff)
    case self.codec

    # Convert u-law into signed PCM
    when IAX_CODEC_G711_MULAW
      Rex::Proto::IAX2::Codecs::MuLaw.decode(buff)

    # Convert a-law into signed PCM
    when IAX_CODEC_G711_ALAW
      Rex::Proto::IAX2::Codecs::ALaw.decode(buff)

    # Linear little-endian signed PCM is our native format
    when IAX_CODEC_LINEAR_PCM
      buff

    # Unsupported codec, return empty
    else
      dprint("UNKNOWN CODEC: #{self.codec.inspect}")
      ''
    end
  end

  def audio_packet_data(pkt)
    (pkt[0,1].unpack("C")[0] & 0x80 == 0) ? pkt[4,pkt.length-4] : pkt[12,pkt.length-12]
  end

end
end
end
end
