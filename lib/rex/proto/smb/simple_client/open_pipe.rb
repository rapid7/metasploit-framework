# -*- coding: binary -*-

module Rex
module Proto
module SMB
class SimpleClient

class OpenPipe < OpenFile

  # Valid modes are: 'trans' and 'rw'
  attr_accessor :mode

  def initialize(*args)
    super(*args)
    self.mode = 'rw'
    @buff = ''
  end

  def read_buffer(length, offset=0)
    length ||= @buff.length
    @buff.slice!(0, length)
  end

  def read_ruby_smb(length, offset, depth = 0)
    if length.nil?
      max_size = client.open_files[client.last_file_id].size
      fptr = offset

      chunk = [max_size, chunk_size].min

      data = client.read(file_id, fptr, chunk).pack('C*')
      fptr = data.length

      while data.length < max_size
        if (max_size - data.length) < chunk
          chunk = max_size - data.length
        end
        data << client.read(file_id, fptr, chunk).pack('C*')
        fptr = data.length
      end
    else
      begin
        client.read(file_id, offset, length).pack('C*')
      rescue RubySMB::Error::UnexpectedStatusCode => e
        if e.message == 'STATUS_PIPE_EMPTY' && depth < 20
          read_ruby_smb(length, offset, depth + 1)
        else
          raise e
        end
      end
    end
  end

  def read(length = nil, offset = 0)
    case self.mode
    when 'trans'
      read_buffer(length, offset)
    when 'rw'
      super(length, offset)
    else
      raise ArgumentError
    end
  end

  def write(data, offset = 0)

    case self.mode

    when 'trans'
      if self.client.is_a?(RubySMB::Client)
        raise NotImplementedError, '\'trans\' mode is not supported by RubySMB'
      end
      write_trans(data, offset)
    when 'rw'
      super(data, offset)
    else
      raise ArgumentError
    end
  end

  def write_trans(data, offset=0)
    ack = self.client.trans_named_pipe(self.file_id, data)
    doff = ack['Payload'].v['DataOffset']
    dlen = ack['Payload'].v['DataCount']
    @buff << ack.to_s[4+doff, dlen]
  end

  def peek_ruby_smb
    self.client.last_file.peek_available
  end

  # This will only return the bytes available and does not receive available data
  STATUS_BUFFER_OVERFLOW = 0x80000005
  STATUS_PIPE_BROKEN     = 0xc000014b
  def peek_rex_smb
    setup = [0x23, self.file_id].pack('vv')
    # Must ignore errors since we expect STATUS_BUFFER_OVERFLOW
    pkt = self.client.trans_maxzero('\\PIPE\\', '', '', 2, setup, false, true, true)
    if pkt['Payload']['SMB'].v['ErrorClass'] == STATUS_PIPE_BROKEN
      raise IOError
    end
    avail = 0
    begin
      avail = pkt.to_s[pkt['Payload'].v['ParamOffset']+4, 2].unpack('v')[0]
    rescue
    end

    if (avail == 0) and (pkt['Payload']['SMB'].v['ErrorClass'] == STATUS_BUFFER_OVERFLOW)
      avail = self.client.default_max_buffer_size
    end
    avail
  end

  def peek
    if self.client.is_a?(RubySMB::Client)
      avail = peek_ruby_smb
    else
      avail = peek_rex_smb
    end
    avail
  end
end
end
end
end
end
