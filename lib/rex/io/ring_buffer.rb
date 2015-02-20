# -*- coding: binary -*-
#
# This class implements a ring buffer with "cursors" in the form of sequence numbers.
# To use this class, pass in a file descriptor and a ring size, the class will read
# data from the file descriptor and store it in the ring. If the ring becomes full,
# the oldest item will be overwritten. To emulate a stream interface, call read_data
# to grab the last sequence number and any buffered data, call read_data again,
# passing in the sequence number and all data newer than that sequence will be
# returned, along with a new sequence to read from.
#

require 'rex/socket'

module Rex
module IO

class RingBuffer

  attr_accessor :queue     # The data queue, essentially an array of two-element arrays, containing a sequence and data buffer
  attr_accessor :seq       # The next available sequence number
  attr_accessor :fd        # The associated socket or IO object for this ring buffer
  attr_accessor :size      # The number of available slots in the queue
  attr_accessor :mutex     # The mutex locking access to the queue
  attr_accessor :beg       # The index of the earliest data fragment in the ring
  attr_accessor :cur       # The sequence number of the earliest data fragment in the ring
  attr_accessor :monitor   # The thread handle of the built-in monitor when used
  attr_accessor :monitor_thread_error  # :nodoc: #

  #
  # Create a new ring buffer
  #
  def initialize(socket, opts={})
    self.size  = opts[:size] || (1024 * 4)
    self.fd    = socket
    self.seq   = 0
    self.beg   = 0
    self.cur   = 0
    self.queue = Array.new( self.size )
    self.mutex = Mutex.new
  end

  def inspect
    "#<Rex::IO::RingBuffer @size=#{size} @fd=#{fd} @seq=#{seq} @beg=#{beg} @cur=#{cur}>"
  end

  #
  # Start the built-in monitor, not called when used in a larger framework
  #
  def start_monitor
    self.monitor = monitor_thread if not self.monitor
  end

  #
  # Stop the built-in monitor
  #
  def stop_monitor
    self.monitor.kill if self.monitor
    self.monitor = nil
  end

  #
  # The built-in monitor thread (normally unused with Metasploit)
  #
  def monitor_thread
    Thread.new do
      begin
      while self.fd
        buff = self.fd.get_once(-1, 1.0)
        next if not buff
        store_data(buff)
      end
      rescue ::Exception => e
        self.monitor_thread_error = e
      end
    end
  end

  #
  # Push data back into the associated stream socket. Logging must occur
  # elsewhere, this function is simply a passthrough.
  #
  def put(data, opts={})
    self.fd.put(data, opts={})
  end

  #
  # The clear_data method wipes the ring buffer
  #
  def clear_data
    self.mutex.synchronize do
      self.seq   = 0
      self.beg   = 0
      self.cur   = 0
      self.queue = Array.new( self.size )
    end
  end

  #
  # The store_data method is used to insert data into the ring buffer.
  #
  def store_data(data)
    self.mutex.synchronize do
      # self.cur points to the array index of queue containing the last item
      # adding data will result in cur + 1 being used to store said data
      # if cur is larger than size - 1, it will wrap back around. If cur
      # is *smaller* beg, beg is increemnted to cur + 1 (and wrapped if
      # necessary

      loc = 0
      if self.seq > 0
        loc = ( self.cur + 1 ) % self.size

        if loc <= self.beg
          self.beg = (self.beg + 1) % self.size
        end
      end

      self.queue[loc] = [self.seq += 1, data]
      self.cur = loc
    end
  end

  #
  # The read_data method returns a two element array with the new reader cursor (a sequence number)
  # and the returned data buffer (if any). A result of nil/nil indicates that no data is available
  #
  def read_data(ptr=nil)
    self.mutex.synchronize do

    # Verify that there is data in the queue
    return [nil,nil] if not self.queue[self.beg]

    # Configure the beginning read pointer (sequence number, not index)
    ptr ||= self.queue[self.beg][0]
    return [nil,nil] if not ptr

    # If the pointer is below our baseline, we lost some data, so jump forward
    if ptr < self.queue[self.beg][0]
      ptr = self.queue[self.beg][0]
    end

    # Calculate how many blocks exist between the current sequence number
    # and the requested pointer, this becomes the number of blocks we will
    # need to read to satisfy the result. Due to the mutex block, we do
    # not need to scan to find the sequence of the starting block or
    # check the sequence of the ending block.
    dis = self.seq - ptr

    # If the requested sequnce number is less than our base pointer, it means
    # that no new data is available and we should return empty.
    return [nil,nil] if dis < 0

    # Calculate the beginning block index and number of blocks to read
    off = ptr - self.queue[self.beg][0]
    set = (self.beg + off) % self.size


    # Build the buffer by reading forward by the number of blocks needed
    # and return the last read sequence number, plus one, as the new read
    # pointer.
    buff = ""
    cnt  = 0
    lst  = ptr
    ptr.upto(self.seq) do |i|
      block = self.queue[ (set + cnt) % self.size ]
      lst,data = block[0],block[1]
      buff += data
      cnt += 1
    end

    return [lst + 1, buff]

    end
  end

  #
  # The base_sequence method returns the earliest sequence number in the queue. This is zero until
  # all slots are filled and the ring rotates.
  #
  def base_sequence
    self.mutex.synchronize do
      return 0 if not self.queue[self.beg]
      return self.queue[self.beg][0]
    end
  end

  #
  # The last_sequence method returns the "next" sequence number where new data will be
  # available.
  #
  def last_sequence
    self.seq
  end

  #
  # The create_steam method assigns a IO::Socket compatible object to the ringer buffer
  #
  def create_stream
    Stream.new(self)
  end

  #
  # The select method returns when there is a chance of new data
  # XXX: This is mostly useless and requires a rewrite to use a
  #      real select or notify mechanism
  #
  def select
    ::IO.select([ self.fd ], nil, [ self.fd ], 0.10)
  end

  #
  # The wait method blocks until new data is available
  #
  def wait(seq)
    nseq = nil
    while not nseq
      nseq,data = read_data(seq)
      select
    end
  end

  #
  # The wait_for method blocks until new data is available or the timeout is reached
  #
  def wait_for(seq,timeout=1)
    begin
      ::Timeout.timeout(timeout) do
        wait(seq)
      end
    rescue ::Timeout::Error
    end
  end

  #
  # This class provides a backwards compatible "stream" socket that uses
  # the parents ring buffer.
  #
  class Stream
    attr_accessor :ring
    attr_accessor :seq
    attr_accessor :buff

    def initialize(ring)
      self.ring = ring
      self.seq  = ring.base_sequence
      self.buff = ''
    end

    def read(len=nil)
      if len and self.buff.length >= len
        data = self.buff.slice!(0,len)
        return data
      end

      while true
        lseq, data = self.ring.read_data( self.seq )
        return if not lseq

        self.seq  = lseq
        self.buff << data
        if len
          if self.buff.length >= len
            return self.buff.slice!(0,len)
          else
            IO.select(nil, nil, nil, 0.25)
            next
          end
        end

        data = self.buff
        self.buff = ''

        return data

        # Not reached
        break
      end

    end

    def write(data)
      self.ring.write(data)
    end
  end

end

end
end

=begin

server = Rex::Socket.create_tcp_server('LocalPort' => 0)
lport  = server.getsockname[2]
client = Rex::Socket.create_tcp('PeerHost' => '127.0.0.1', 'PeerPort' => lport)
conn   = server.accept

r = Rex::IO::RingBuffer.new(conn, {:size => 1024*1024})
client.put("1")
client.put("2")
client.put("3")

s,d = r.read_data

client.put("4")
client.put("5")
client.put("6")
s,d = r.read_data(s)

client.put("7")
client.put("8")
client.put("9")
s,d = r.read_data(s)

client.put("0")
s,d = r.read_data(s)

test_counter = 11
1.upto(100) do
  client.put( "X" )
  test_counter += 1
end

sleep(1)

s,d = r.read_data
p s
p d

fdata = ''
File.open("/bin/ls", "rb") do |fd|
  fdata = fd.read(fd.stat.size)
  fdata = fdata * 10
  client.put(fdata)
end

sleep(1)

s,vdata = r.read_data(s)

if vdata != fdata
  puts "DATA FAILED"
else
  puts "DATA VERIFIED"
end

r.clear_data

a = r.create_stream
b = r.create_stream

client.put("ABC123")
sleep(1)

p a.read
p b.read

client.put("$$$$$$")
sleep(1)

p a.read
p b.read

c = r.create_stream
p c.read

=end


