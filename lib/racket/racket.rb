# $Id: racket.rb 14 2008-03-02 05:42:30Z warchild $
#
# Copyright (c) 2008, Jon Hart 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY Jon Hart ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Jon Hart BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

require 'socket'

require 'racket/racketpart'
require 'racket/tlv'
require 'racket/lv'
require 'racket/vt'
require 'racket/misc'
require 'racket/l2'
require 'racket/l3'
require 'racket/l4'
require 'racket/l5'


module Racket
class Racket

  attr_accessor :iface, :mtu, :timeout
  attr_accessor :layers, :payload

  @@loaded_pcaprub = false
  begin
  	require 'pcaprub'
  	@@loaded_pcaprub = true
  rescue ::LoadError
  end

  def initialize(payload="")
    @layers = []
    @mtu = 1500
    @timeout = 10
    @payload = payload
    1.upto(7) do |l|
      self.class.send(:define_method, "layer#{l}", lambda { @layers[l] })
      self.class.send(:define_method, "l#{l}", lambda { @layers[l] })
      self.class.send(:define_method, "layer#{l}=", lambda { |x| @layers[l] = x; })
      self.class.send(:define_method, "l#{l}=", lambda { |x| @layers[l] = x; })
    end
  end

  # Assemble all the pieces of this Racket as a string, ready for sending.
  def pack
    last_payload = ""
    orig_payload = ""
    @layers.compact.reverse.each do |l|
      # save the original payload
      orig_payload = l.payload
      # tack on the last payload in
      # case fix needs it...
      l.payload += last_payload
      if (l.autofix?)
        l.fix!
      end

      if (l.payload == orig_payload + last_payload)
        # payload was not modified by fix, so reset it to what
        # it used to be
        l.payload = orig_payload
      else
        # payload was modified by fix.  chop off what we added.
        # XXX: this assumes that what we added is still at the end.  
        # XXX: this is not always true
        l.payload = l.payload.slice(0, l.payload.length - last_payload.length)
      end

      # save this layer for the next guy
      last_payload += l
      
    end
    
    payload = ""
    @layers.compact.each do |l|
      payload += l
    end
    payload
  end

  def pretty
    s = ""
    @layers.compact.each do |l|
      s << "#{l.class}: "
      s << l.pretty
      s << "\n"
    end
    s
  end
      

  # Attempt to figure out which of send2 or send3 needs to be called.
  def sendpacket
    if (@layers[2])
      send2
    else
      send3
    end
  end

  # Write raw layer2 frames
  def send2
    if(not @@loaded_pcaprub)
      raise RuntimeError, "Could not initialize the pcaprub library"	
	end
	
    begin
      p = Pcap::open_live(@iface, @mtu, false, @timeout)
    rescue Exception => e
      puts "Pcap: can't open device '#{@iface}' (#{e})"
      return
    end

    begin
      b = p.inject(pack)
      p.close
      return b
    rescue Exception => e
      puts "Pcap: error while sending packet on '#{@iface}' (#{e})"
    end
  end

  # Write raw layer3 frames
  def send3
    begin
      s = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
      #s.setsockopt(Socket::SOL_IP, Socket::IP_HDRINCL, true)
    rescue Errno::EPERM
      $stderr.puts "Must run #{$0} as root."
      exit!
    end

    return s.send(pack, 0, Socket.pack_sockaddr_in(1024, @layers[3].dst_ip))
  end
end

end

# vim: set ts=2 et sw=2:
