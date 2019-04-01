# -*- coding: binary -*-
require 'logger'
require 'net/dns/names/names'
require 'net/dns/dns'
require 'net/dns/header'
require 'net/dns/question'
require 'net/dns/rr'

module Net # :nodoc:
  module DNS 
    
    # =Name
    #
    # Net::DNS::Packet - DNS packet object class
    #
    # =Synopsis
    # 
    #   require 'net/dns/packet'
    #
    # =Description
    # 
    # The Net::DNS::Packet class represents an entire DNS packet,
    # divided in his main section: 
    # 
    # * Header (instance of Net::DNS::Header)
    # * Question (array of Net::DNS::Question objects)
    # * Answer, Authority, Additional (each formed by an array of Net::DNS::RR 
    #   objects)
    #
    # You can use this class whenever you need to create a DNS packet, whether
    # in an user application, in a resolver instance (have a look, for instance,
    # at the Net::DNS::Resolver#send method) or for a nameserver.
    #
    # Some example:
    #
    #   # Create a packet
    #   packet = Net::DNS::Packet.new("www.example.com")
    #   mx = Net::DNS::Packet.new("example.com", Net::DNS::MX)
    #
    #   # Getting packet binary data, suitable for network transmission
    #   data = packet.data
    #
    # A packet object can be created from binary data too, like an 
    # answer packet just received from a network stream:
    #
    #   packet = Net::DNS::Packet::parse(data)
    #
    # Each part of a packet can be gotten by the right accessors:
    #
    #   header = packet.header     # Instance of Net::DNS::Header class
    #   question = packet.question # Instance of Net::DNS::Question class
    #   
    #   # Iterate over additional RRs
    #   packet.additional.each do |rr|
    #     puts "Got an #{rr.type} record"
    #   end
    #
    # Some iterators have been written to easy the access of those RRs, 
    # which are often the most important. So instead of doing:
    #
    #   packet.answer.each do |rr|
    #     if rr.type == Net::DNS::RR::Types::A
    #       # do something with +rr.address+
    #     end
    #   end
    #
    # we can do:
    #
    #   packet.each_address do |ip|
    #     # do something with +ip+
    #   end
    #
    # Be sure you don't miss all the iterators in the class documentation.
    #
    # =Logging facility
    # 
    # As Net::DNS::Resolver class, Net::DNS::Packet class has its own logging
    # facility too. It work in the same way the other one do, so you can 
    # maybe want to override it or change the file descriptor.
    #
    #   packet = Net::DNS::Packet.new("www.example.com")
    #   packet.logger = $stderr
    #
    #   # or even
    #   packet.logger = Logger.new("/tmp/packet.log")
    #
    # If the Net::DNS::Packet class is directly instantiated by the Net::DNS::Resolver
    # class, like the great majority of the time, it will use the same logger facility.
    #
    # Logger level will be set to Logger::Debug if $DEBUG variable is set.
    #
    # =Error classes
    #
    # Some error classes has been defined for the Net::DNS::Packet class,
    # which are listed here to keep a light and browsable main documentation.
    # We have:
    #
    # * PacketArgumentError: Generic argument error for class Net::DNS::Packet
    # * PacketError: Generic Packet error
    #
    # =Copyright
    # 
    # Copyright (c) 2006 Marco Ceresa
    #
    # All rights reserved. This program is free software; you may redistribute 
    # it and/or modify it under the same terms as Ruby itself.
    #
    class Packet

      include Names
      
      attr_reader :header, :question, :answer, :authority, :additional
      attr_reader :answerfrom, :answersize

      # Create a new instance of Net::DNS::Packet class. Arguments are the
      # canonical name of the resourse, an optional type field and an optional
      # class field. The record type and class can be omitted; they default 
      # to +A+ and +IN+.
      #
      #   packet = Net::DNS::Packet.new("www.example.com")
      #   packet = Net::DNS::Packet.new("example.com", Net::DNS::MX)
      #   packet = Net::DNS::Packet.new("example.com",Net::DNS::TXT,Net::DNS::CH)
      #
      # This class no longer instantiate object from binary data coming from
      # network streams. Please use Net::DNS::Packet.new_from_data instead.
      # 
      def initialize(name,type=Net::DNS::A,cls=Net::DNS::IN)
        @header = Net::DNS::Header.new(:qdCount => 1)
        @question = [Net::DNS::Question.new(name,type,cls)]
        @answer = []
        @authority = []
        @additional = []
        @logger = Logger.new $stdout
        @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN
      end

      # Create a new instance of Net::DNS::Packet class from binary data, taken
      # out by a network stream. For example:
      #
      #   # udp_socket is an UDPSocket waiting for a response
      #   ans = udp_socket.recvfrom(1500)
      #   packet = Net::DNS::Packet::parse(ans)
      #
      # An optional +from+ argument can be used to specify the information
      # of the sender. If data is passed as is from a Socket#recvfrom call,
      # the method will accept it.
      #
      # Be sure that your network data is clean from any UDP/TCP header, 
      # expecially when using RAW sockets.
      # 
      def Packet.parse(*args)
        o = allocate
        o.send(:new_from_data, *args)
        o
      end
      

      # Checks if the packet is a QUERY packet
      def query?
        @header.opCode == Net::DNS::Header::QUERY
      end

      # Return the packet object in binary data, suitable
      # for sending across a network stream.
      #
      #   packet_data = packet.data
      #   puts "Packet is #{packet_data.size} bytes long"
      #
      def data
        qdcount=ancount=nscount=arcount=0
        data = @header.data
        headerlength = data.length
        
        @question.each do |question|
          data += question.data
          qdcount += 1
        end
        @answer.each do |rr|
          data += rr.data#(data.length)
          ancount += 1
        end
        @authority.each do |rr|
          data += rr.data#(data.length)
          nscount += 1
        end
        @additional.each do |rr|
          next if rr.nil?
          data += rr.data#(data.length)
          arcount += 1
        end
        
        @header.qdCount = qdcount
        @header.anCount = ancount
        @header.nsCount = nscount
        @header.arCount = arcount

        @header.data + data[Net::DNS::HFIXEDSZ..data.size]
      end

      # Same as Net::DNS::Packet#data, but implements name compression
      # (see RFC1025) for a considerable save of bytes.
      #
      #   packet = Net::DNS::Packet.new("www.example.com")
      #   puts "Size normal is #{packet.data.size} bytes"
      #   puts "Size compressed is #{packet.data_comp.size} bytes"
      #   
      def data_comp
        offset = 0
        compnames = {}
        qdcount=ancount=nscount=arcount=0
        data = @header.data
        headerlength = data.length

        @question.each do |question|
          str,offset,names = question.data
          data += str
          compnames.update(names)
          qdcount += 1
        end
        
        @answer.each do |rr|
          str,offset,names = rr.data(offset,compnames)
          data += str
          compnames.update(names)
          ancount += 1
        end
        
        @authority.each do |rr|
          str,offset,names = rr.data(offset,compnames)
          data += str
          compnames.update(names)
          nscount += 1
        end
        
        @additional.each do |rr|
          str,offset,names = rr.data(offset,compnames)
          data += str
          compnames.update(names)
          arcount += 1
        end
        
        @header.qdCount = qdcount
        @header.anCount = ancount
        @header.nsCount = nscount
        @header.arCount = arcount
        
        @header.data + data[Net::DNS::HFIXEDSZ..data.size]
      end
      
      # Inspect method
      def inspect
        retval = ""
        if @answerfrom != "0.0.0.0:0" and @answerfrom
          retval << ";; Answer received from #@answerfrom (#{@answersize} bytes)\n;;\n"
        end
        
        retval << ";; HEADER SECTION\n"
        retval << @header.inspect
        
        retval << "\n"
        section = (@header.opCode == "UPDATE") ? "ZONE" : "QUESTION"
        retval << ";; #{section} SECTION (#{@header.qdCount} record#{@header.qdCount == 1 ? '' : 's'}):\n"
        @question.each do |qr|
          retval << ";; " + qr.inspect + "\n"
        end

        unless @answer.size == 0
          retval << "\n"
          section = (@header.opCode == "UPDATE") ? "PREREQUISITE" : "ANSWER"
          retval << ";; #{section} SECTION (#{@header.anCount} record#{@header.anCount == 1 ? '' : 's'}):\n"
          @answer.each do |rr|
            retval << rr.inspect + "\n"
          end
        end

        unless @authority.size == 0
          retval << "\n"
          section = (@header.opCode == "UPDATE") ? "UPDATE" : "AUTHORITY"
          retval << ";; #{section} SECTION (#{@header.nsCount} record#{@header.nsCount == 1 ? '' : 's'}):\n"
          @authority.each do |rr|
            retval << rr.inspect + "\n"
          end
        end
        
        unless @additional.size == 0
          retval << "\n"
          retval << ";; ADDITIONAL SECTION (#{@header.arCount} record#{@header.arCount == 1 ? '' : 's'}):\n"
          @additional.each do |rr|
            retval << rr.inspect + "\n"
          end
        end
        
        retval
      end

      
      # Wrapper to Header#truncated?
      #
      def truncated?
        @header.truncated?
      end
            
      # Assing a Net::DNS::Header object to a Net::DNS::Packet 
      # instance.
      #
      def header=(object)
        if object.kind_of? Net::DNS::Header
          @header = object
        else
          raise PacketArgumentError, "Argument must be a Net::DNS::Header object"
        end
      end
      
      # Assign a Net::DNS::Question object, or an array of 
      # Questions objects, to a Net::DNS::Packet instance.
      #
      def question=(object)
        case object
        when Array
          if object.all? {|x| x.kind_of? Net::DNS::Question}
            @question = object
          else
            raise PacketArgumentError, "Some of the elements is not an Net::DNS::Question object"
          end
        when Net::DNS::Question
          @question = [object]
        else
          raise PacketArgumentError, "Invalid argument, not a Question object nor an array of objects"
        end
      end

      # Assign a Net::DNS::RR object, or an array of 
      # RR objects, to a Net::DNS::Packet instance answer 
      # section.
      #
      def answer=(object)
        case object
        when Array
          if object.all? {|x| x.kind_of? Net::DNS::RR}
            @answer = object
          else
            raise PacketArgumentError, "Some of the elements is not an Net::DNS::RR object"
          end
        when Net::DNS::RR
          @answer = [object]
        else
          raise PacketArgumentError, "Invalid argument, not a RR object nor an array of objects"
        end
      end

      # Assign a Net::DNS::RR object, or an array of 
      # RR objects, to a Net::DNS::Packet instance additional 
      # section.
      #
      def additional=(object)
        case object
        when Array
          if object.all? {|x| x.kind_of? Net::DNS::RR}
            @additional = object
          else
            raise PacketArgumentError, "Some of the elements is not an Net::DNS::RR object"
          end
        when Net::DNS::RR
          @additional = [object]
        else
          raise PacketArgumentError, "Invalid argument, not a RR object nor an array of objects"
        end
      end

      # Assign a Net::DNS::RR object, or an array of 
      # RR objects, to a Net::DNS::Packet instance authority 
      # section.
      #
      def authority=(object)
        case object
        when Array
          if object.all? {|x| x.kind_of? Net::DNS::RR}
            @authority = object
          else
            raise PacketArgumentError, "Some of the elements is not an Net::DNS::RR object"
          end
        when Net::DNS::RR
          @authority = [object]
        else
          raise PacketArgumentError, "Invalid argument, not a RR object nor an array of objects"
        end
      end
      
      # Iterate for every address in the +answer+ section of a 
      # Net::DNS::Packet object.
      #
      #   packet.each_address do |ip|
      #     ping ip.to_s
      #   end
      #
      # As you can see in the documentation for Net::DNS::RR::A class,
      # the address returned is an instance of IPAddr class. 
      #
      def each_address
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::A
          yield elem.address
        end
      end
      
      # Iterate for every nameserver in the +answer+ section of a 
      # Net::DNS::Packet object.
      #
      #   packet.each_nameserver do |ns|
      #     puts "Nameserver found: #{ns}"
      #   end
      #
      def each_nameserver
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::NS
          yield elem.nsdname
        end
      end
      
      # Iterate for every exchange record in the +answer+ section 
      # of a Net::DNS::Packet object.
      #
      #   packet.each_mx do |pref,name|
      #     puts "Mail exchange #{name} has preference #{pref}"
      #   end
      #
      def each_mx
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::MX
          yield elem.preference,elem.exchange
        end
      end
      
      # Iterate for every canonical name in the +answer+ section 
      # of a Net::DNS::Packet object.
      #
      #   packet.each_cname do |cname|
      #     puts "Canonical name: #{cname}"
      #   end
      #
      def each_cname
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::CNAME
          yield elem.cname
        end
      end
      
      # Iterate for every pointer in the +answer+ section of a 
      # Net::DNS::Packet object.
      #
      #   packet.each_ptr do |ptr|
      #     puts "Pointer for resource: #{ptr}"
      #   end
      #
      def each_ptr
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::PTR
          yield elem.ptrdname
        end
      end

      # Chacks whether a query has returned a NXDOMAIN error,
      # meaning the domain name queried doesn't exists.
      #
      #   %w[a.com google.com ibm.com d.com].each do |domain|
      #     response = Net::DNS::Resolver.new.send(domain)
      #     puts "#{domain} doesn't exist" if response.nxdomain?
      #   end
      #     #=> a.com doesn't exist
      #     #=> d.com doesn't exist
      #
      def nxdomain?
        header.rCode == Net::DNS::Header::NAME
      end
      
      private

      # New packet from binary data
      def new_from_data(data, from = nil)
        unless from
          if data.kind_of? Array
            data,from = data
          else
            from = [0,0,"0.0.0.0","unknown"]
          end
        end
          
        @answerfrom = from[2] + ":" + from[1].to_s
        @answersize = data.size
        @logger = Logger.new $stdout
        @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN
        
        #------------------------------------------------------------
        # Header section
        #------------------------------------------------------------
        offset = Net::DNS::HFIXEDSZ 
        @header = Net::DNS::Header.parse(data[0..offset-1])

        @logger.debug ";; HEADER SECTION"
        @logger.debug @header.inspect

        #------------------------------------------------------------
        # Question section
        #------------------------------------------------------------
        section = @header.opCode == "UPDATE" ? "ZONE" : "QUESTION"
        @logger.debug ";; #{section} SECTION (#{@header.qdCount} record#{@header.qdCount == 1 ? '': 's'})"

        @question = []
        @header.qdCount.times do
          qobj,offset = parse_question(data,offset)
          @question << qobj
          @logger.debug ";; #{qobj.inspect}"
        end

        #------------------------------------------------------------
        # Answer/prerequisite section
        #------------------------------------------------------------
        section = @header.opCode == "UPDATE" ? "PREREQUISITE" : "ANSWER"
        @logger.debug ";; #{section} SECTION (#{@header.qdCount} record#{@header.qdCount == 1 ? '': 's'})"
        
        @answer = []
        @header.anCount.times do
          rrobj,offset = Net::DNS::RR.parse_packet(data,offset)
          @answer << rrobj
          @logger.debug rrobj.inspect
        end

        #------------------------------------------------------------
        # Authority/update section
        #------------------------------------------------------------
        section = @header.opCode == "UPDATE" ? "UPDATE" : "AUTHORITY"
        @logger.debug ";; #{section} SECTION (#{@header.nsCount} record#{@header.nsCount == 1 ? '': 's'})"
        
        @authority = []
        @header.nsCount.times do
          rrobj,offset = Net::DNS::RR.parse_packet(data,offset)
          @authority << rrobj
          @logger.debug rrobj.inspect          
        end
        
        #------------------------------------------------------------
        # Additional section
        #------------------------------------------------------------
        @logger.debug ";; ADDITIONAL SECTION (#{@header.arCount} record#{@header.arCount == 1 ? '': 's'})"    
        
        @additional = []
        @header.arCount.times do
          rrobj,offset = Net::DNS::RR.parse_packet(data,offset)
          @additional << rrobj
          @logger.debug rrobj.inspect
        end
        
      end # new_from_data
      
      
      # Parse question section
      def parse_question(data,offset)
        size = (dn_expand(data,offset)[1]-offset) + 2*Net::DNS::INT16SZ
        return [Net::DNS::Question.parse(data[offset,size]), offset+size]
      rescue StandardError => err
        raise PacketError, "Caught exception, maybe packet malformed => #{err}"
      end

    end # class Packet
    
  end # module DNS
end # module Net

class PacketError < StandardError # :nodoc:
end
class PacketArgumentError < ArgumentError # :nodoc:
end
