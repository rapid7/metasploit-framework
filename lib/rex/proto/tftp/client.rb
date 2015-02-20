# -*- coding: binary -*-
require 'rex/socket'
require 'rex/proto/tftp'
require 'tempfile'

module Rex
module Proto
module TFTP

#
# TFTP Client class
#
# Note that TFTP has blocks, and so does Ruby. Watch out with the variable names!
#
# The big gotcha right now is that setting the mode between octet, netascii, or
# anything else doesn't actually do anything other than declare it to the
# server.
#
# Also, since TFTP clients act as both clients and servers, we use two
# threads to handle transfers, regardless of the direction. For this reason,
# the transfer actions are nonblocking; if you need to see the
# results of a transfer before doing something else, check the boolean complete
# attribute and any return data in the :status attribute. It's a little
# weird like that.
#
# Finally, most (all?) clients will alter the data in netascii mode in order
# to try to conform to the RFC standard for what "netascii" means, but there are
# ambiguities in implementations on things like if nulls are allowed, what
# to do with Unicode, and all that. For this reason, "octet" is default, and
# if you want to send "netascii" data, it's on you to fix up your source data
# prior to sending it.
#
class Client

  attr_accessor :local_host, :local_port, :peer_host, :peer_port
  attr_accessor :threads, :context, :server_sock, :client_sock
  attr_accessor :local_file, :remote_file, :mode, :action
  attr_accessor :complete, :recv_tempfile, :status
  attr_accessor :block_size # This definitely breaks spec, should only use for fuzz/sploit.

  # Returns an array of [code, type, msg]. Data packets
  # specifically will /not/ unpack, since that would drop any trailing spaces or nulls.
  def parse_tftp_response(str)
    return nil unless str.length >= 4
    ret = str.unpack("nnA*")
    ret[2] = str[4,str.size] if ret[0] == OpData
    return ret
  end

  def initialize(params)
    self.threads = []
    self.local_host = params["LocalHost"] || "0.0.0.0"
    self.local_port = params["LocalPort"] || (1025 + rand(0xffff-1025))
    self.peer_host = params["PeerHost"] || (raise ArgumentError, "Need a peer host.")
    self.peer_port = params["PeerPort"] || 69
    self.context = params["Context"]
    self.local_file = params["LocalFile"]
    self.remote_file = params["RemoteFile"] || (::File.split(self.local_file).last if self.local_file)
    self.mode = params["Mode"] || "octet"
    self.action = params["Action"] || (raise ArgumentError, "Need an action.")
    self.block_size = params["BlockSize"] || 512
  end

  #
  # Methods for both upload and download
  #

  def start_server_socket
    self.server_sock = Rex::Socket::Udp.create(
      'LocalHost' => local_host,
      'LocalPort' => local_port,
      'Context'   => context
    )
    if self.server_sock and block_given?
      yield "Started TFTP client listener on #{local_host}:#{local_port}"
    end
    self.threads << Rex::ThreadFactory.spawn("TFTPServerMonitor", false) {
      if block_given?
        monitor_server_sock {|msg| yield msg}
      else
        monitor_server_sock
      end
    }
  end

  def monitor_server_sock
    yield "Listening for incoming ACKs" if block_given?
    res = self.server_sock.recvfrom(65535)
    if res and res[0]
      code, type, data = parse_tftp_response(res[0])
      if code == OpAck and self.action == :upload
        if block_given?
          yield "WRQ accepted, sending the file." if type == 0
          send_data(res[1], res[2]) {|msg| yield msg}
        else
          send_data(res[1], res[2])
        end
      elsif code == OpData and self.action == :download
        if block_given?
          recv_data(res[1], res[2], data) {|msg| yield msg}
        else
          recv_data(res[1], res[2], data)
        end
      elsif code == OpError
        yield("Aborting, got error type:%d, message:'%s'" % [type, data]) if block_given?
        self.status = {:error => [code, type, data]}
      else
        yield("Aborting, got code:%d, type:%d, message:'%s'" % [code, type, data]) if block_given?
        self.status = {:error => [code, type, data]}
      end
    end
    stop
  end

  def monitor_client_sock
    res = self.client_sock.recvfrom(65535)
    if res[1] # Got a response back, so that's never good; Acks come back on server_sock.
      code, type, data = parse_tftp_response(res[0])
      yield("Aborting, got code:%d, type:%d, message:'%s'" % [code, type, data]) if block_given?
      self.status = {:error => [code, type, data]}
      stop
    end
  end

  def stop
    self.complete = true
    begin
      self.server_sock.close
      self.client_sock.close
      self.server_sock = nil
      self.client_sock = nil
      self.threads.each {|t| t.kill}
    rescue
      nil
    end
  end

  #
  # Methods for download
  #

  def rrq_packet
    req = [OpRead, self.remote_file, self.mode]
    packstr = "na#{self.remote_file.length+1}a#{self.mode.length+1}"
    req.pack(packstr)
  end

  def ack_packet(blocknum=0)
    req = [OpAck, blocknum].pack("nn")
  end

  def send_read_request(&block)
    self.status = nil
    self.complete = false
    if block_given?
      start_server_socket {|msg| yield msg}
    else
      start_server_socket
    end
    self.client_sock = Rex::Socket::Udp.create(
      'PeerHost'  => peer_host,
      'PeerPort'  => peer_port,
      'LocalHost' => local_host,
      'LocalPort' => local_port,
      'Context'   => context
    )
    self.client_sock.sendto(rrq_packet, peer_host, peer_port)
    self.threads << Rex::ThreadFactory.spawn("TFTPClientMonitor", false) {
      if block_given?
        monitor_client_sock {|msg| yield msg}
      else
        monitor_client_sock
      end
    }
    until self.complete
      return self.status
    end
  end

  def recv_data(host, port, first_block)
    self.recv_tempfile = Rex::Quickfile.new('msf-tftp')
    recvd_blocks = 1
    if block_given?
      yield "Source file: #{self.remote_file}, destination file: #{self.local_file}"
      yield "Received and acknowledged #{first_block.size} in block #{recvd_blocks}"
    end
    if block_given?
      write_and_ack_data(first_block,1,host,port) {|msg| yield msg}
    else
      write_and_ack_data(first_block,1,host,port)
    end
    current_block = first_block
    while current_block.size == 512
      res = self.server_sock.recvfrom(65535)
      if res and res[0]
        code, block_num, current_block = parse_tftp_response(res[0])
        if code == 3
          if block_given?
            write_and_ack_data(current_block,block_num,host,port) {|msg| yield msg}
          else
            write_and_ack_data(current_block,block_num,host,port)
          end
          recvd_blocks += 1
        else
          yield("Aborting, got code:%d, type:%d, message:'%s'" % [code, type, msg]) if block_given?
          stop
        end
      end
    end
    if block_given?
      yield("Transferred #{self.recv_tempfile.size} bytes in #{recvd_blocks} blocks, download complete!")
    end
    self.status = {:success => [
      self.local_file,
      self.remote_file,
      self.recv_tempfile.size,
      recvd_blocks.size]
    }
    self.recv_tempfile.close
    stop
  end

  def write_and_ack_data(data,blocknum,host,port)
    self.recv_tempfile.write(data)
    self.recv_tempfile.flush
    req = ack_packet(blocknum)
    self.server_sock.sendto(req, host, port)
    yield "Received and acknowledged #{data.size} in block #{blocknum}" if block_given?
  end

  #
  # Methods for upload
  #

  def wrq_packet
    req = [OpWrite, self.remote_file, self.mode]
    packstr = "na#{self.remote_file.length+1}a#{self.mode.length+1}"
    req.pack(packstr)
  end

  # Note that the local filename for uploading need not be a real filename --
  # if it begins with DATA: it can be any old string of bytes. If it's missing
  # completely, then just quit.
  def blockify_file_or_data
    if self.local_file =~ /^DATA:(.*)/m
      data = $1
    elsif ::File.file?(self.local_file) and ::File.readable?(self.local_file)
      data = ::File.open(self.local_file, "rb") {|f| f.read f.stat.size} rescue []
    else
      return []
    end
    data_blocks = data.scan(/.{1,#{block_size}}/m)
    # Drop any trailing empty blocks
    if data_blocks.size > 1 and data_blocks.last.empty?
      data_blocks.pop
    end
    return data_blocks
  end

  def send_write_request(&block)
    self.status = nil
    self.complete = false
    if block_given?
      start_server_socket {|msg| yield msg}
    else
      start_server_socket
    end
    self.client_sock = Rex::Socket::Udp.create(
      'PeerHost'  => peer_host,
      'PeerPort'  => peer_port,
      'LocalHost' => local_host,
      'LocalPort' => local_port,
      'Context'   => context
    )
    self.client_sock.sendto(wrq_packet, peer_host, peer_port)
    self.threads << Rex::ThreadFactory.spawn("TFTPClientMonitor", false) {
      if block_given?
        monitor_client_sock {|msg| yield msg}
      else
        monitor_client_sock
      end
    }
    until self.complete
      return self.status
    end
  end

  def send_data(host,port)
    self.status = {:write_allowed => true}
    data_blocks = blockify_file_or_data()
    if data_blocks.empty?
      yield "Closing down since there is no data to send." if block_given?
      self.status = {:success => [self.local_file, self.local_file, 0, 0]}
      return nil
    end
    sent_data = 0
    sent_blocks = 0
    expected_blocks = data_blocks.size
    expected_size = data_blocks.join.size
    if block_given?
      yield "Source file: #{self.local_file =~ /^DATA:/ ? "(Data)" : self.remote_file}, destination file: #{self.remote_file}"
      yield "Sending #{expected_size} bytes (#{expected_blocks} blocks)"
    end
    data_blocks.each_with_index do |data_block,idx|
      req = [OpData, (idx + 1), data_block].pack("nnA*")
      if self.server_sock.sendto(req, host, port) > 0
        sent_data += data_block.size
      end
      res = self.server_sock.recvfrom(65535)
      if res
        code, type, msg = parse_tftp_response(res[0])
        if code == 4
          sent_blocks += 1
          yield "Sent #{data_block.size} bytes in block #{sent_blocks}" if block_given?
        else
          if block_given?
            yield "Got an unexpected response: Code:%d, Type:%d, Message:'%s'. Aborting." % [code, type, msg]
          end
          break
        end
      end
    end
    if block_given?
      if(sent_data == expected_size)
        yield("Transferred #{sent_data} bytes in #{sent_blocks} blocks, upload complete!")
      else
        yield "Upload complete, but with errors."
      end
    end
    if sent_data == expected_size
    self.status = {:success => [
        self.local_file,
        self.remote_file,
        sent_data,
        sent_blocks
      ] }
    end
  end

end

end
end
end
