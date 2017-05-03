# -*- coding: binary -*-
# $Id: gsiplib.rb 15548 2012-06-29 06:08:20Z rapid7 $
#Gamasec SIP Library
#Author : Fatih Ozavci - gamasec.net/fozavci
#Github : github.com/fozavci/gamasec-sipmodules

require 'rex/socket'
require 'timeout'

module SIP

#
#
#
#SIP Socket Class
#
#
#

class Socket
	attr_accessor :listen_addr, :listen_port, :context
	attr_accessor :sock, :thread, :dest_addr, :dest_port
	
	def initialize(listen_port = 5060, listen_addr = '0.0.0.0', dest_port = 5060, dest_addr = nil, context = {})
        
		self.listen_addr = listen_addr
		self.listen_port = listen_port
		if dest_addr == nil 
			raise ::Rex::ArgumentError, 'Destination IP Address Required'
		else
			self.dest_addr = dest_addr
		end
		self.dest_port = dest_port
        self.context = context
		self.sock = nil	
        start	
	end
    
	#
	# Start the SIPSocket 
	#    
	def start
		self.sock = Rex::Socket::Udp.create(
			'LocalHost' => listen_addr,
			'LocalPort' => listen_port,
			'Context'   => context
			)
	end


	#
	# Stop the SIPSocket 
	#
	def stop
		self.thread.kill
		self.sock.close rescue nil # might be closed already
	end

	#
	#Converting Errors to Message
	#
	def convert_error(err)
		case err
			when :cred_required
				return "Credentials Required"
			when :no_response
				return "No Response"
			when :succeed_withoutlogin
				return "Request Succeed without Login Information"			
            when :ringing
				return "Ringing"
            when :user_busy
				return "User is Busy"
            when :succeed
				return "Request Succeed"
			when :failed
				return "Authentication Failed"
			when :send_error
				return "Request Sending is Failed"
			when :server_error
				return "Internal Server Error"
			when :nodigest
				return "No Digest Found in '401 Unauthorized' Response"
			when :authorization_error
				return "Authorization Error"
			when :decline_error
				return "Server Declined"
			when :protocol_error
				return "Protocol Error"
		else
			return "Unknown Error #{err}"
		end	
	end
	
	#
	# Sending Register
	# 
    def register(req_options={})        
	    login = req_options["login"] || false
	    result,rdata,rdebug,rawdata,callopts=generic_request("REGISTER",req_options)
	    if :received and rdata != nil
		    case rdata['resp']
			    when "200"
				    result=:succeed_withoutlogin
			    when "401"
				    if login
					    result,rdata,rdebug,rawdata,callopts=auth("REGISTER",rdata,rdebug,rawdata,req_options,callopts)
				    else
					    result=:cred_required
				    end
			    when /^60/
				    result=:decline_error
			    else
				    result=:protocol_error
		    end
	    end
	    return result,rdata,rdebug,rawdata,callopts
    end
	
	#
	# Sending Options
	#    
    def send_options(req_options={})        
        return generic_request("OPTIONS",req_options)
    end
	
	#
	# Sending Subscribe
	#    
    def send_subscribe(req_options={})
	    return generic_request("SUBSCRIBE",req_options)
    end		

	#
	# Sending ACK
	#    
    def send_ack(req_options={})
	    return generic_request("ACK",req_options,no_response=true)
    end		

  	#
	# Sending Invite
	#    
    def send_invite(req_options={})
        login = req_options["login"] || false
        loginmethod = req_options["loginmethod"] || "INVITE"

        if login and loginmethod == "REGISTER"
            #From and TO fields should be same for REGISTER
            regopts=req_options.clone
            regopts['from']=regopts['user']
            regopts['to']=regopts['user']
            reg_result,rdata,rdebug,rawdata,callopts=register(regopts)

            req_options['callopts']=callopts if callopts != nil

            # Cleaning Old Session Data
            req_options['nonce'] = nil
            req_options['callopts'].delete('seq')
            req_options['callopts'].delete('callid')
            req_options['callopts'].delete('tag')
        end
        


        result,rdata,rdebug,rawdata,callopts=generic_request("INVITE",req_options)


        if :received and rdata != nil 
            result = parse_rescode(rdata)
            case result
            when :cred_required
                if login
                    ack_options=req_options.clone
                    ack_options['callopts']=callopts.clone
                    ack_options['callopts'].delete('seq')
                    send_ack(ack_options)
                    
                    result,rdata,rdebug,rawdata,callopts=auth("INVITE",rdata,rdebug,rawdata,req_options,callopts) 
                    if :received and rdata != nil 
                        result = parse_rescode(rdata)
                    else
                        result = :protocol_error
                    end
                end
            when :succeed
                result = :succeed_withoutlogin if reg_result != :succeed and result == :succeed            
    	    else
		        result = :protocol_error
            end
	    end
        return result,rdata,rdebug,rawdata,callopts
    end			

protected


	#
	#Result Code Parsing
	#
    def parse_rescode(rdata)
	    case rdata['resp']
	    when "200"
		    result=:succeed
	    when "180"
		    result=:ringing
	    when "401"
		    result=:cred_required			    
	    when "486"
		    result=:user_busy	
	    when /^60/
		    result=:decline_error
	    when /^50/
		    result=:server_error
	    else
		    result=:protocol_error
	    end
    end


	#
	#Generic SIP Request Sending
	#	
	def generic_request(method,req_options={},no_response=false)
		callopts,send_state=send_data(method,req_options)
        return nil if no_response
		return :send_error if send_state == :error
    
        rdata,rdebug,rawdata=resp_get(method)		
		if rdata == nil 
			return :no_response
		else
			return :received,rdata,rdebug,rawdata,callopts
        end
    end
	
	
	#
	#Authentication
	#
	def auth(method,rdata,rdebug,rawdata,req_options,callopts=nil)
		if rdata['digest']
			req_options['nonce']=rdata['digest']['nonce']
			req_options['digest_realm']=rdata['digest']['realm']
			req_options['callopts']=callopts if callopts != nil

			#Sending Request with Nonce
			callopts,send_state=send_data(method,req_options)
			return :send_error,rdata,rdebug,rawdata,callopts if send_state == :error
			
			#Receiving Authentication Response
			rdata,rdebug,rawdata=resp_get(method,rdebug)		
			return :no_response,rdata,rdebug,rawdata,callopts if rdata == nil
			
			case rdata['resp']
				when "200"
					return :succeed,rdata,rdebug,rawdata,callopts
				when "/^48/"
					return :succeed,rdata,rdebug,rawdata,callopts
				when "/^18/"
					return :succeed,rdata,rdebug,rawdata,callopts
				when /^401/
					return :failed,rdata,rdebug,rawdata,callopts
				else
					return :authorization_error,rdata,rdebug,rawdata,callopts
			end
		else
			return :nodigest,rdata,rdebug,rawdata,callopts
		end
	end
	
	#
	# Receiving Data
	#    
	def recv_data
            r = self.sock.recvfrom(65535, 3)
            rdata,rawdata=parse_reply(r)
            return rdata,rawdata
    end
	
	#Response Check
	def resp_get(method,rdebug=[])
        possible= /^18|^20|^40|^48|^60|^50/
        rdata,rawdata=recv_data
		while (rdata != nil and !(rdata['resp'] =~ possible))			
			rdebug << rdata
			rdata,rawdata=recv_data
			break if rdebug.length > 9
		end		
		return rdata,rdebug,rawdata
	end
		
 	#
	# Nonce Calculation
	#
	def	nonce_resp(user,realm,password,nonce,uri,req_type)
		hash1 = Digest::MD5.hexdigest("#{user}:#{realm}:#{password}")
        hash2 = Digest::MD5.hexdigest("#{req_type}:#{uri}")
        response=Digest::MD5.hexdigest("#{hash1}:#{nonce}:#{hash2}")
	end

      
	#
	# Sending Data
	#    
    def send_data(req_type,req_options)
        data,callopts = create_req(req_type,req_options)
        begin
          self.sock.sendto(data, dest_addr, dest_port, 0)
            send_state=:success
        rescue ::Interrupt
            send_state=:error
            raise $!
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
            send_state=:error
          nil
        end
        return callopts,send_state
    end


    #
	# Prepare Request
	#    
    def create_req(req_type,req_options)
        realm=req_options['realm'] || dest_addr
        user=req_options['user'] 
        from=req_options['from']  || user
        fromname=req_options['fromname']  || nil
        to=req_options['to'] || user           
        password=req_options['password'] || nil
        nonce=req_options['nonce'] || nil 
        callopts=req_options['callopts'] || {}
        seq=callopts['seq'].to_i+1 || seq=1
        callid=callopts['callid'] || callid="call#{Rex::Text.rand_text_alphanumeric(30)}"
        tag=callopts['tag'] || tag="tag#{Rex::Text.rand_text_alphanumeric(20)}"
        branch=callopts['branch'] || branch="branch#{Rex::Text.rand_text_alphanumeric(50)}"
        
		case req_type 
        when 'SUBSCRIBE' 
			uri="sip:#{user}@#{realm}"
        when 'INVITE'
            uri="sip:#{to}@#{realm}"
		else
			uri="sip:#{realm}"
		end

        data = "#{req_type} #{uri} SIP/2.0\r\n"
        data << "Via: SIP/2.0/UDP #{listen_addr}:#{listen_port};branch=#{branch};rport\r\n" 
        data << "Max-Forwards: 20\r\n"
        data << "To: <sip:#{to}@#{realm}>\r\n"
        data << "From: \"#{fromname}\" <sip:#{from}@#{realm}>;tag=#{tag}\r\n"
        data << "Call-ID: #{callid}@#{listen_addr}\r\n"
        data << "CSeq: #{seq} #{req_type}\r\n"
        data << "Contact: <sip:#{from}@#{listen_addr}:#{listen_port}>\r\n"
        data << "User-Agent: Test Agent\r\n"
        data << "Supported: 100rel,replaces\r\n"       
        data << "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING,PRACK\r\n"
        data << "Expires: 3600\r\n"
		
        if req_options['headers']
	        req_options['headers'].split("|||").each { |h|
		        data << "#{h}\r\n"
	        }
        end

        if req_type == 'SUBSCRIBE'
	        data << "Event: message-summary\r\n"
	        data << "Accept: application/simple-message-summary\r\n"
        end

        if nonce !=nil
            resp=nonce_resp(user,req_options['digest_realm'],password,nonce,uri,req_type)
            data << "Authorization: Digest username=\"#{user}\",realm=\"#{req_options['digest_realm']}\",nonce=\"#{nonce}\",uri=\"#{uri}\",response=\"#{resp}\"\r\n"
        end
        
        if req_type == 'INVITE'
            sdp_ID=Rex::Text.rand_text_numeric(9)
            s="Source"

            idata = "v=0\r\n"
            idata << "o=- #{sdp_ID} #{sdp_ID} IN IP4 #{listen_addr}\r\n"
            idata << "s=#{s}\r\n"
            idata << "c=IN IP4 #{listen_addr}\r\n"
            idata << "t=0 0\r\n"
            idata << "m=audio 8000 RTP/AVP 0 8 96 3 13 101\r\n"
            idata << "a=rtpmap:0 PCMU/8000\r\n"
            idata << "a=rtpmap:8 PCMA/8000\r\n"
            idata << "a=rtpmap:96 G726-32/8000\r\n"
            idata << "a=rtpmap:3 GSM/8000\r\n"
            idata << "a=rtpmap:13 CN/8000\r\n"
            idata << "a=rtpmap:101 telephone-event/8000\r\n"
            idata << "a=fmtp:101 0-16\r\n"
            idata << "a=sendrecv\r\n"
            idata << "a=direction:active\r\n"
            idata << "\r\n"

            data << "Content-Type: application/sdp\r\n"
            data << "Content-Length: #{idata.length}\r\n\r\n"
            data << idata

        else
            data << "Content-Length: 0\r\n\r\n"
        end
        
        callopts={ "callid" => callid, "seq" =>seq, "tag" => tag, "branch" => branch }
        return data,callopts
    end    
    
	#
	# Parsing Response
	#  
	
	def parse_reply(pkt)

		return if not pkt[1]
		rdata={}
		rawdata=pkt[0]

		rdata["source"] = "#{pkt[1].split(":")[3]}:#{pkt[2]}"

		rdata["resp"] = pkt[0].split(/\s+/)[1]
        rdata["resp_msg"] = pkt[0].split("\r")[0]


		if(pkt[0] =~ /^User-Agent:\s*(.*)$/i)
			rdata["agent"] = "#{$1.strip}"
		end

		if(pkt[0] =~ /^Allow:\s+(.*)$/i)
			rdata["verbs"] = "#{$1.strip}"
		end

		if(pkt[0] =~ /^Server:\s+(.*)$/)
			rdata["server"] = "#{$1.strip}"
		end

		if(pkt[0] =~ /^Proxy-Require:\s+(.*)$/)
			rdata["proxy"] = "#{$1.strip}"
		end
		
		if(pkt[0] =~ /^WWW-Authenticate:\s*(.*)$/i)
			data="#{$1.strip.gsub("Digest ","")}"
			rdata["digest"] = {}
			data.split(",").each { |d| rdata["digest"][d.split("=")[0].gsub(" ","")]=d.split("=")[1].gsub("\"",'')}
		end
        if(pkt[0] =~ /^From:\s+(.*)$/)
			rdata["from"] = "#{$1.strip.split(";")[0].gsub(/[<sip:|>]/,"")}"
		end
        if(pkt[0] =~ /^To:\s+(.*)$/)
			rdata["to"] = "#{$1.strip.split(";")[0].gsub(/[<sip:|>]/,"")}"
		end
		return rdata,rawdata
	end    
      
end

end
