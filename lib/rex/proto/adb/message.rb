# -*- coding: binary -*-

##
# ADB protocol support
##

module Rex
module Proto
module ADB

# A Message for the ADB protocol. For documentation see:
# https://android.googlesource.com/platform/system/core/+/master/adb/protocol.txt
class Message

  WORD_WIDTH = 4 # bytes
  WORD_PACK = 'L<'

  attr_accessor :command
  attr_accessor :arg0
  attr_accessor :arg1
  attr_accessor :data

  def initialize(arg0, arg1, data)
    self.command = self.class::COMMAND if defined?(self.class::COMMAND)
    self.arg0 = arg0
    self.arg1 = arg1
    self.data = data + "\0"
  end

  def data_check
    # this check is implemented in adb/transport.cpp, in the send_packet method.
    # it is not crc32 as the docs make it appear, it is just a 32bit sum.
    data.bytes.inject(&:+) & 0xffffffff
  end

  def magic
    command_word ^ 0xffffffff
  end

  def command_word
    command.unpack(WORD_PACK)[0]
  end

  def send_recv(socket)
    socket.print self.serialize
    Message.read socket
  end

  def serialize
    [
      command_word,
      arg0,
      arg1,
      data.bytes.length,
      data_check,
      magic
    ].pack(WORD_PACK+'*') + data
  end

  def to_s
    [
      "command=#{command}",
      "arg0=0x#{arg0.to_s(16)}",
      "arg1=0x#{arg1.to_s(16)}",
      "data=#{data}"
    ].join("\n")
  end

  def self.read(socket)
    header = socket.recvfrom(6 * WORD_WIDTH)[0]
    command = header[0, WORD_WIDTH]
    arg0 = header[WORD_WIDTH, WORD_WIDTH].unpack(WORD_PACK)[0]
    arg1 = header[WORD_WIDTH*2, WORD_WIDTH].unpack(WORD_PACK)[0]
    payload_len = header[WORD_WIDTH*3, WORD_WIDTH].unpack(WORD_PACK)[0]
    payload = socket.recvfrom(payload_len)[0]

    klass = MESSAGE_TYPES.find { |klass| klass::COMMAND == command }
    if klass.nil?
      raise "Invalid adb command: #{command}"
    end

    message = klass.allocate
    message.command = command
    message.arg0 = arg0
    message.arg1 = arg1
    message.data = payload
    message
  end

  #
  # Subclasses inside Message:: namespace for specific message types
  #

  class Connect < Message
    COMMAND = "CNXN"
    DEFAULT_VERSION = 0x01000000
    DEFAULT_MAXDATA = 4096
    DEFAULT_IDENTITY = "host::"

    def initialize(version=DEFAULT_VERSION,
                   maxdata=DEFAULT_MAXDATA,
                   system_identity_string=DEFAULT_IDENTITY)
      super
    end
  end

  class Auth < Message
    COMMAND = "AUTH"
    TYPE_TOKEN = 1
    TYPE_SIGNATURE = 2

    def initialize(type, data)
      super(type, 0, data)
    end
  end

  class Open < Message
    COMMAND = "OPEN"

    def initialize(local_id, destination)
      super(local_id, 0, destination)
    end
  end

  class Ready < Message
    COMMAND = "OKAY"

    def initialize(local_id, remote_id)
      super(local_id, remote_id, "")
    end
  end

  class Write < Message
    COMMAND = "WRTE"

    def initialize(local_id, remote_id, data)
      super
    end
  end

  class Close < Message
    COMMAND = "CLSE"

    def initialize(local_id, remote_id)
      super(local_id, remote_id, "")
    end
  end

  class Sync < Message
    COMMAND = "SYNC"

    def initialize(online, sequence)
      super(online, sequence, "")
    end
  end

  # Avoid a dependency on Rails's nice Class#subclasses
  MESSAGE_TYPES = [Connect, Auth, Open, Ready, Write, Close, Sync]

end # Message

end # ADB
end # Proto
end # Rex
