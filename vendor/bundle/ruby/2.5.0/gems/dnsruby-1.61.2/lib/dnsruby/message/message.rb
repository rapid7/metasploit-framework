# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require 'dnsruby/name'
require 'dnsruby/resource/resource'

module Dnsruby
  #  ===Defines a DNS packet.
  # 
  #  RFC 1035 Section 4.1, RFC 2136 Section 2, RFC 2845
  # 
  #  ===Sections
  #  Message objects have five sections:
  # 
  # * The header section, a Dnsruby::Header object.
  # 
  #       msg.header=Header.new(...)
  #       header = msg.header
  # 
  # * The question section, an array of Dnsruby::Question objects.
  # 
  #       msg.add_question(Question.new(domain, type, klass))
  #       msg.each_question do |question|  ....   end
  # 
  # * The answer section, an array of Dnsruby::RR objects.
  # 
  #       msg.add_answer(RR.create({:name    => 'a2.example.com',
  # 		      :type    => 'A', :address => '10.0.0.2'}))
  #       msg.each_answer {|answer| ... }
  # 
  # * The authority section, an array of Dnsruby::RR objects.
  # 
  #       msg.add_authority(rr)
  #       msg.each_authority {|rr| ... }
  # 
  # * The additional section, an array of Dnsruby::RR objects.
  # 
  #       msg.add_additional(rr)
  #       msg.each_additional {|rr| ... }
  # 
  #  In addition, each_resource iterates the answer, additional
  #  and authority sections :
  # 
  #       msg.each_resource {|rr| ... }
  # 
  #  ===Packet format encoding
  # 
  #       Dnsruby::Message#encode
  #       Dnsruby::Message::decode(data)
  # 
  #  ===Additional information
  #  security_level records the current DNSSEC status of this Message.
  #  answerfrom records the server which this Message was received from.
  #  cached records whether this response came from the cache.
  # 
  class Message

    #  The security level (see RFC 4035 section 4.3)
    class SecurityLevel < CodeMapper
      INDETERMINATE = -2
      BOGUS = -1
      UNCHECKED = 0
      INSECURE = 1
      SECURE = 2
      update
    end

    #  If dnssec is set on, then each message will have the security level set
    #  To find the precise error (if any), call Dnsruby::Dnssec::validate(msg) -
    #  the resultant exception will define the error.
    attr_accessor :security_level

    #  If there was a problem verifying this message with DNSSEC, then securiy_error
    #  will hold a description of the problem. It defaults to ''
    attr_accessor :security_error

    #  If the Message was returned from the cache, the cached flag will be set
    #  true. It will be false otherwise.
    attr_accessor :cached



    #  Create a new Message. Takes optional name, type and class
    # 
    #  type defaults to A, and klass defaults to IN
    # 
    # *  Dnsruby::Message.new('example.com') # defaults to A, IN
    # *  Dnsruby::Message.new('example.com', 'AAAA')
    # *  Dnsruby::Message.new('example.com', Dnsruby::Types.PTR, 'HS')
    # 
    def initialize(*args)
      @header = Header.new()
      #       @question = Section.new(self)
      @question = []
      @answer = Section.new(self)
      @authority = Section.new(self)
      @additional = Section.new(self)
      @tsigstate = :Unsigned
      @signing = false
      @tsigkey = nil
      @answerfrom = nil
      @answerip = nil
      @send_raw = false
      @do_validation = true
      @do_caching = true
      @security_level = SecurityLevel.UNCHECKED
      @security_error = nil
      @cached = false
      type = Types::A
      klass = Classes::IN
      if (args.length > 0)
        name = args[0]
        if (args.length > 1)
          type = Types.new(args[1])
          if (args.length > 2)
            klass = Classes.new(args[2])
          end
        end
        add_question(name, type, klass)
      end
    end

    # The question section, an array of Dnsruby::Question objects.
    attr_reader :question

    # The answer section, an array of Dnsruby::RR objects.
    attr_reader :answer
    # The authority section, an array of Dnsruby::RR objects.
    attr_reader :authority
    # The additional section, an array of Dnsruby::RR objects.
    attr_reader :additional
    # The header section, a Dnsruby::Header object.
    attr_accessor :header

    # If this Message is a response from a server, then answerfrom contains the address of the server
    attr_accessor :answerfrom

    # If this Message is a response from a server, then answerfrom contains the IP address of the server
    attr_accessor :answerip

    # If this Message is a response from a server, then answersize contains the size of the response
    attr_accessor :answersize

    # If this message has been verified using a TSIG RR then tsigerror contains
    # the error code returned by the TSIG verification. The error will be an RCode
    attr_accessor :tsigerror

    # Can be
    # * :Unsigned - the default state
    # * :Signed - the outgoing message has been signed
    # * :Verified - the incoming message has been verified by TSIG
    # * :Intermediate - the incoming message is an intermediate envelope in a TCP session
    # in which only every 100th envelope must be signed
    # * :Failed - the incoming response failed verification
    attr_accessor :tsigstate

    # --
    attr_accessor :tsigstart
    # ++

    # Set send_raw if you wish to send and receive the response to this Message
    # with no additional processing. In other words, if set, then Dnsruby will
    # not touch the Header of the outgoing Message. This option does not affect
    # caching or dnssec validation
    # 
    # This option should not normally be set.
    attr_accessor :send_raw

    # do_validation is set by default. If you do not wish dnsruby to validate
    # this message (on a Resolver with @dnssec==true), then set do_validation
    # to false. This option does not affect caching, or the header options
    attr_accessor :do_validation

    # do_caching is set by default. If you do not wish dnsruby to inspect the
    # cache before sending the query, nor cache the result of the query, then
    # set do_caching to false.
    attr_accessor :do_caching

    def get_exception
      exception = nil
      if rcode == RCode.NXDOMAIN
        exception = NXDomain.new
      elsif rcode == RCode.SERVFAIL
        exception = ServFail.new
      elsif rcode == RCode.FORMERR
        exception = FormErr.new
      elsif rcode == RCode.NOTIMP
        exception = NotImp.new
      elsif rcode == RCode.REFUSED
        exception = Refused.new
      elsif rcode == RCode.NOTZONE
        exception = NotZone.new
      elsif rcode == RCode.NOTAUTH
        exception = NotAuth.new
      elsif rcode == RCode.NXRRSET
        exception = NXRRSet.new
      elsif rcode == RCode.YXRRSET
        exception = YXRRSet.new
      elsif rcode == RCode.YXDOMAIN
        exception = YXDomain.new
      elsif rcode >= RCode.BADSIG && rcode <= RCode.BADALG
        return VerifyError.new # @TODO@
      end
      exception
    end

    def ==(other)
      other.kind_of?(Message) &&
          @header      == other.header &&
          @question[0] == other.question[0] &&
          @answer      == other.answer &&
          @authority   == other.authority &&
          @additional  == other.additional
    end

    def remove_additional
      @additional = Section.new(self)
      @header.arcount = 0
    end

    #  Return the first rrset of the specified attributes in the message
    def rrset(name, type, klass = Classes::IN)
      [@answer, @authority, @additional].each do |section|
        if (rrset = section.rrset(name, type, klass)).length > 0
          return rrset
        end
      end
      RRSet.new
    end

    #  Return the rrsets of the specified type in the message
    def rrsets(type, klass=Classes::IN)
      rrsetss = []
      [@answer, @authority, @additional].each do |section|
        if (rrsets = section.rrsets(type, klass)).length > 0
          rrsets.each { |rrset| rrsetss.push(rrset) }
        end
      end
      rrsetss
    end

    #  Return a hash, with the section as key, and the RRSets in that
    #  section as the data : {section => section_rrs}
    def section_rrsets(type = nil, include_opt = false)
      ret = {}
      %w(answer authority additional).each do |section|
        ret[section] = self.send(section).rrsets(type, include_opt)
      end
      ret
    end

    #  Add a new Question to the Message. Takes either a Question,
    #  or a name, and an optional type and class.
    # 
    # * msg.add_question(Question.new('example.com', 'MX'))
    # * msg.add_question('example.com') # defaults to Types.A, Classes.IN
    # * msg.add_question('example.com', Types.LOC)
    def add_question(question, type=Types.A, klass=Classes.IN)
      unless question.kind_of?(Question)
        question = Question.new(question, type, klass)
      end
      @question << question
      update_counts
    end

    def each_question
      @question.each {|rec|
        yield rec
      }
    end

    def update_counts # :nodoc:all
      @header.ancount = @answer.length
      @header.arcount = @additional.length
      @header.qdcount = @question.length
      @header.nscount = @authority.length
    end

    def _add_answer(rr, force = false)
      if force || (! @answer.include?(rr))
        @answer << rr
        update_counts
      end
    end; private :_add_answer

    # Adds an RR to the answer section unless it already occurs.
    def add_answer(rr) #:nodoc: all
      _add_answer(rr)
    end

    # When adding an RR to a Dnsruby::Message, add_answer checks to see if it already occurs,
    # and, if so, does not add it again. This method adds the record whether or not
    # it already occurs.  This is needed in order to add
    # a SOA record twice for an AXFR response.
    def add_answer!(rr)
      _add_answer(rr, true)
    end


    def each_answer
      @answer.each {|rec|
        yield rec
      }
    end

    def add_authority(rr) #:nodoc: all
      unless @authority.include?(rr)
        @authority << rr
        update_counts
      end
    end

    def each_authority
      @authority.each {|rec|
        yield rec
      }
    end

    def add_additional(rr) #:nodoc: all
      unless @additional.include?(rr)
        @additional << rr
        update_counts
      end
    end

    def each_additional
      @additional.each { |rec| yield rec }
    end

    #  Yields each section (question, answer, authority, additional)
    def each_section
      [@answer, @authority, @additional].each { |section| yield section}
    end

    #  Calls each_answer, each_authority, each_additional
    def each_resource
      each_answer {|rec| yield rec}
      each_authority {|rec| yield rec}
      each_additional {|rec| yield rec}
    end

    #  Returns the TSIG record from the ADDITIONAL section, if one is present.
    def tsig
      if @additional.last
        if @additional.last.rr_type == Types.TSIG
          return @additional.last
        end
      end
      nil
    end

    #  Sets the TSIG to sign this message with. Can either be a Dnsruby::RR::TSIG
    #  object, or it can be a (name, key) tuple, or it can be a hash which takes
    #  Dnsruby::RR::TSIG attributes (e.g. name, key, fudge, etc.)
    def set_tsig(*args)
      if args.length == 1
        if args[0].instance_of?(RR::TSIG)
          @tsigkey = args[0]
        elsif args[0].instance_of?(Hash)
          @tsigkey = RR.create({:type=>'TSIG', :klass=>'ANY'}.merge(args[0]))
        else
          raise ArgumentError.new('Wrong type of argument to Dnsruby::Message#set_tsig - should be TSIG or Hash')
        end
      elsif args.length == 2
        @tsigkey = RR.create({:type=>'TSIG', :klass=>'ANY', :name=>args[0], :key=>args[1]})
      else
        raise ArgumentError.new('Wrong number of arguments to Dnsruby::Message#set_tsig')
      end
    end

    # Was this message signed by a TSIG?
    def signed?
      @tsigstate == :Signed ||
          @tsigstate == :Verified ||
          @tsigstate == :Failed
    end

    #  If this message was signed by a TSIG, was the TSIG verified?
    def verified?
      @tsigstate == :Verified
    end

    def get_opt
      @additional.detect { |r| r.type == Types::OPT }
    end

    def rcode
      rcode = @header.get_header_rcode
      opt = get_opt
      if opt
        rcode = rcode.code + (opt.xrcode.code << 4)
        rcode = RCode.new(rcode)
      end
      rcode
    end

    def to_s
      s = ''  # the output string to return

      if @answerfrom && (! @answerfrom.empty?)
        s << ";; Answer received from #{@answerfrom} (#{@answersize} bytes)\n;;\n"
      end

      s << ";; Security Level : #{@security_level.string}\n"

      #  OPT pseudosection? EDNS flags, udpsize
      opt = get_opt

      if opt
        s << @header.to_s_with_rcode(rcode) << "\n#{opt}\n"
      else
        s << "#{@header}\n"
      end

      section = (@header.opcode == OpCode.UPDATE) ? 'ZONE' : 'QUESTION'
      s <<  ";; #{section} SECTION (#{@header.qdcount}  record#{@header.qdcount == 1 ? '' : 's'})\n"
      each_question { |qr| s << ";; #{qr}\n" }

      if @answer.size > 0
        s << "\n"
        section = (@header.opcode == OpCode.UPDATE) ? 'PREREQUISITE' : 'ANSWER'
        s << ";; #{section} SECTION (#{@header.ancount}  record#{@header.ancount == 1 ? '' : 's'})\n"
        each_answer { |rr| s << "#{rr}\n" }
      end

      if @authority.size > 0
        s << "\n"
        section = (@header.opcode == OpCode.UPDATE) ? 'UPDATE' : 'AUTHORITY'
        s << ";; #{section} SECTION (#{@header.nscount}  record#{@header.nscount == 1 ? '' : 's'})\n"
        each_authority { |rr| s << rr.to_s + "\n" }
      end

      if (@additional.size > 0 && !opt) || (@additional.size > 1)
        s << "\n;; ADDITIONAL SECTION (#{@header.arcount}  record#{@header.arcount == 1 ? '' : 's'})\n"
        each_additional { |rr|
          if rr.type != Types::OPT
            s << rr.to_s+ "\n"
          end
        }
      end

      s
    end


    def old_to_s
      retval = ''

      if (@answerfrom != nil && @answerfrom != '')
        retval = retval + ";; Answer received from #{@answerfrom} (#{@answersize} bytes)\n;;\n"
      end
      retval = retval + ";; Security Level : #{@security_level.string}\n"

      retval = retval + ";; HEADER SECTION\n"

      #  OPT pseudosection? EDNS flags, udpsize
      opt = get_opt
      if (!opt)
        retval = retval + @header.old_to_s
      else
        retval = retval + @header.old_to_s_with_rcode(rcode())
      end
      retval = retval + "\n"

      if (opt)
        retval = retval + opt.to_s
        retval = retval + "\n"
      end

      section = (@header.opcode == OpCode.UPDATE) ? "ZONE" : "QUESTION"
      retval = retval +  ";; #{section} SECTION (#{@header.qdcount}  record#{@header.qdcount == 1 ? '' : 's'})\n"
      each_question { |qr|
        retval = retval + ";; #{qr.to_s}\n"
      }

      if (@answer.size > 0)
        retval = retval + "\n"
        section = (@header.opcode == OpCode.UPDATE) ? "PREREQUISITE" : "ANSWER"
        retval = retval + ";; #{section} SECTION (#{@header.ancount}  record#{@header.ancount == 1 ? '' : 's'})\n"
        each_answer { |rr|
          retval = retval + rr.to_s + "\n"
        }
      end

      if (@authority.size > 0)
        retval = retval + "\n"
        section = (@header.opcode == OpCode.UPDATE) ? "UPDATE" : "AUTHORITY"
        retval = retval + ";; #{section} SECTION (#{@header.nscount}  record#{@header.nscount == 1 ? '' : 's'})\n"
        each_authority { |rr|
          retval = retval + rr.to_s + "\n"
        }
      end

      if ((@additional.size > 0 && !opt) || (@additional.size > 1))
        retval = retval + "\n"
        retval = retval + ";; ADDITIONAL SECTION (#{@header.arcount}  record#{@header.arcount == 1 ? '' : 's'})\n"
        each_additional { |rr|
          if (rr.type != Types::OPT)
            retval = retval + rr.to_s+ "\n"
          end
        }
      end

      retval
    end

    #  Signs the message. If used with no arguments, then the message must have already
    #  been set (set_tsig). Otherwise, the arguments can either be a Dnsruby::RR::TSIG
    #  object, or a (name, key) tuple, or a hash which takes
    #  Dnsruby::RR::TSIG attributes (e.g. name, key, fudge, etc.)
    # 
    #  NOTE that this method should only be called by the resolver, rather than the
    #  client code. To use signing from the client, call Dnsruby::Resolver#tsig=
    def sign!(*args) #:nodoc: all
      if args.length > 0
        set_tsig(*args)
        sign!
      else
        if @tsigkey && (@tsigstate == :Unsigned)
          @tsigkey.apply(self)
        end
      end
    end

    #  Return the encoded form of the message
    #  If there is a TSIG record present and the record has not been signed
    #  then sign it
    def encode(canonical=false)
      if @tsigkey && (@tsigstate == :Unsigned) && !@signing
        @signing = true
        sign!
        @signing = false
      end

      return MessageEncoder.new { |msg|
        header = @header
        header.encode(msg)
        @question.each { |q|
          msg.put_name(q.qname)
          msg.put_pack('nn', q.qtype.code, q.qclass.code)
        }
        [@answer, @authority, @additional].each { |rr|
          rr.each { |r|
            msg.put_rr(r, canonical)
          }
        }
      }.to_s
    end

    #  Decode the encoded message
    def Message.decode(m)
      o = Message.new()
      begin
        MessageDecoder.new(m) {|msg|
          o.header = Header.new(msg)
          o.header.qdcount.times {
            question = msg.get_question
            o.question << question
          }
          o.header.ancount.times {
            rr = msg.get_rr
            o.answer << rr
          }
          o.header.nscount.times {
            rr = msg.get_rr
            o.authority << rr
          }
          o.header.arcount.times { |count|
            start = msg.index
            rr = msg.get_rr
            if rr.type == Types::TSIG
              if count != o.header.arcount-1
                Dnsruby.log.Error('Incoming message has TSIG record before last record')
                raise DecodeError.new('TSIG record present before last record')
              end
              o.tsigstart = start # needed for TSIG verification
            end
            o.additional << rr
          }
        }
      rescue DecodeError => e
        #  So we got a decode error
        #  However, we might have been able to fill in many parts of the message
        #  So let's raise the DecodeError, but add the partially completed message
        e.partial_message = o
        raise e
      end
      o
    end

    def clone
      Message.decode(self.encode)
    end

    #  In dynamic update packets, the question section is known as zone and
    #  specifies the zone to be updated.
    alias :zone :question
    alias :add_zone :add_question
    alias :each_zone :each_question

    #  In dynamic update packets, the answer section is known as pre or
    #  prerequisite and specifies the RRs or RRsets which must or
    #  must not preexist.
    alias :pre :answer
    alias :add_pre :add_answer
    alias :each_pre :each_answer

    #  In dynamic update packets, the answer section is known as pre or
    #  prerequisite and specifies the RRs or RRsets which must or
    #  must not preexist.
    alias :prerequisite :pre
    alias :add_prerequisite :add_pre
    alias :each_prerequisite :each_pre

    #  In dynamic update packets, the authority section is known as update and
    #  specifies the RRs or RRsets to be added or delted.
    alias :update :authority
    alias :add_update :add_authority
    alias :each_update :each_authority

  end
end

require 'dnsruby/message/section'
require 'dnsruby/message/header'
require 'dnsruby/message/decoder'
require 'dnsruby/message/encoder'
require 'dnsruby/message/question'
