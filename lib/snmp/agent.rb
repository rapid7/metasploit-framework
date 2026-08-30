#
# Copyright (c) 2004 David R. Halliday
# All rights reserved.
#
# This SNMP library is free software.  Redistribution is permitted under the
# same terms and conditions as the standard Ruby distribution.  See the
# COPYING file in the Ruby distribution for details.
#

require 'snmp'
require 'socket'
require 'logger'

module SNMP

class Agent #:nodoc:all

    def initialize(listen_port=161, max_packet=8000)
        @log = Logger.new(STDOUT)
        @log.level = Logger::DEBUG
        @max_packet = max_packet
        @socket = UDPSocket.open
        @socket.bind(nil, listen_port)
        @mib = MIB::SystemMIB.new
    end
    
    def start
        @log.info "SNMP agent running"
        loop do
            begin
                data, remote_info = @socket.recvfrom(@max_packet)
                puts "Received #{data.length} bytes"
                p data
                message = Message.decode(data)
                case message.pdu
                    when GetRequest
                        response = message.response
                        response.pdu.varbind_list.each do |v|
                            v.value = @mib.get(v.name)
                        end
                    when SetRequest
                        response = message.response
                    else
                        raise "invalid message #{message.to_s}"
                end
                puts "Responding to #{remote_info[3]}:#{remote_info[1]}"
                encoded_message = response.encode
                n=@socket.send(encoded_message, 0, remote_info[3], remote_info[1])
                p encoded_message
            rescue => e
                @log.error e
                shutdown
            end
        end
    end
    
    def shutdown
        @log.info "SNMP agent stopping"
        @socket.close
        exit
    end

    alias stop :shutdown
    
end

end

if $0 == __FILE__
agent = SNMP::Agent.new(1061)
trap("INT") { agent.shutdown }
agent.start
end

