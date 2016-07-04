# -*- coding: binary -*-

require 'rex/proto/adb/message'

module Rex
module Proto
module ADB

class Client

  def initialize(sock, opts = {})
    @sock = sock
    @opts = opts
    @local_id_counter = 0x0a
  end

  def connect
    ADB::Message::Connect.new.send_recv(@sock)
  end

  def exec_cmd(cmd)
    local_id = @local_id_counter += 1
    response = ADB::Message::Open.new(local_id, "shell:"+cmd).send_recv(@sock)
    ADB::Message::Close.new(local_id, response.arg0).send_recv(@sock)
  end

  def read_message
    ADB::Message.read(@sock)
  end

end # Client

end # ADB
end # Proto
end # Rex
