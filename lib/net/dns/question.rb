#---
# $Id: Question.rb,v 1.8 2006/07/28 19:00:03 bluemonk Exp $     
#+++

require 'net/dns/dns'
require 'net/dns/names/names'
require 'net/dns/rr/types'
require 'net/dns/rr/classes'

module Net # :nodoc:
  module DNS 

    #
    # =Name
    #
    # Net::DNS::Question - DNS packet question class
    #
    # =Synopsis
    # 
    #   require 'net/dns/question'
    #
    # =Description
    #
    # This class represent the Question portion of a DNS packet. The number
    # of question entries is stored in the +qdCount+ variable of an Header
    # object. 
    #
    # A new object can be created passing the name of the query and the type
    # of answer desired, plus an optional argument containing the class:
    #
    #   question = Net::DNS::Question.new("google.com.", Net::DNS::A)
    #      #=> "google.com.                   A       IN"
    #
    # Alternatevly, a new object is created when processing a binary
    # packet, as when an answer is received.
    # To obtain the binary data from a question object you can use
    # the method Question#data:
    # 
    #   question.data
    #      #=> "\006google\003com\000\000\001\000\001"
    #
    # A lot of methods were written to keep a compatibility layer with
    # the Perl version of the library, as long as methods name which are
    # more or less the same. 
    #
    # =Error classes
    #
    # Some error classes has been defined for the Net::DNS::Header class,
    # which are listed here to keep a light and browsable main documentation.
    # We have:
    #
    # * QuestionArgumentError: generic argument error
    # * QuestionNameError:     an error in the +name+ part of a Question entry
    #
    # =Copyright
    # 
    # Copyright (c) 2006 Marco Ceresa
    #
    # All rights reserved. This program is free software; you may redistribute 
    # it and/or modify it under the same terms as Ruby itself.
    #
    class Question
      
      include Net::DNS::Names
      
      # +name+ part of a Question entry
      attr_reader :qName 
      # +type+ part of a Question entry
      attr_reader :qType 
      # +class+ part of a Question entry
      attr_reader :qClass 
      
      # Creates a new Net::DNS::Question object:
      #
      #   question = Net::DNS::Question.new("example.com")
      #      #=> "example.com                   A       IN"
      #   question = Net::DNS::Question.new("example.com", Net::DNS::MX)
      #      #=> "example.com                   MX      IN"
      #   question = Net::DNS::Question.new("example.com", Net::DNS::TXT, Net::DNS::HS)
      #      #=> "example.com                   TXT     HS"
      
      # If not specified, +type+ and +cls+ arguments defaults 
      # to Net::DNS::A and Net::DNS::IN respectively.
      #
      def initialize(name,type=Net::DNS::A,cls=Net::DNS::IN)
        @qName = check_name name
        @qType = Net::DNS::RR::Types.new type
        @qClass = Net::DNS::RR::Classes.new cls
      end

      # Return a new Net::DNS::Question object created by
      # parsing binary data, such as an answer from the
      # nameserver.
      #
      #   question = Net::DNS::Question.parse(data)
      #   puts "Queried for #{question.qName} type #{question.qType.to_s}"
      #     #=> Queried for example.com type A
      #
      def self.parse(arg)
        if arg.kind_of? String
          o = allocate
          o.send(:new_from_binary,arg)
          o
        else
          raise QuestionArgumentError, "Wrong argument format, must be a String"
        end
      end

      # Known inspect method with nice formatting
      def inspect
        if @qName.size > 29 then 
          len = @qName.size + 1 
        else
          len = 29
        end
        [@qName,@qClass.to_s,@qType.to_s].pack("A#{len} A8 A8")
      end
      
      # Outputs binary data from a Question object
      #
      #   question.data
      #      #=> "\006google\003com\000\000\001\000\001"
      #
      def data
        [pack_name(@qName),@qType.to_i,@qClass.to_i].pack("a*nn")
      end
      
      # Return the binary data of the objects, plus an offset
      # and an Hash with references to compressed names. For use in 
      # Net::DNS::Packet compressed packet creation.
      #
      def comp_data
        arr = @qName.split(".")
        str = pack_name(@qName)
        string = ""
        names = {}
        offset = Net::DNS::HFIXEDSZ
        arr.size.times do |i|
          x = i+1
          elem = arr[-x]
          len = elem.size
          string = ((string.reverse)+([len,elem].pack("Ca*")).reverse).reverse
          names[string] = offset
          offset += len
        end
        offset += 2 * Net::DNS::INT16SZ
        str += "\000"
        [[str,@qType.to_i,@qClass.to_i].pack("a*nn"),offset,names]
      end
      
      private
      
      def build_qName(str)
        result = ""
        offset = 0
        loop do
          len = str.unpack("@#{offset} C")[0]
          break if len == 0
          offset += 1
          result += str[offset..offset+len-1]
          result += "."
          offset += len
        end
        result
      end
      
      def check_name(name)
        name.strip!
        if name =~ /[^\w\.\-_]/
          raise QuestionNameError, "Question name #{name.inspect} not valid"          
        else
          name
        end
      rescue
        raise QuestionNameError, "Question name #{name.inspect} not valid"                  
      end
      
      def new_from_binary(data)
        str,type,cls = data.unpack("a#{data.size-4}nn")
        @qName = build_qName(str)
        @qType = Net::DNS::RR::Types.new type
        @qClass = Net::DNS::RR::Classes.new cls
      rescue StandardError => e
        raise QuestionArgumentError, "Invalid data: #{data.inspect}\n{e.backtrace}"
      end

    end # class Question
    
  end # class DNS
end # module Net

class QuestionArgumentError < ArgumentError # :nodoc:
end
class QuestionNameError < StandardError # :nodoc:
end
