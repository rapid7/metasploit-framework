require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'Basic HTTP Server',
			'Description' => %q{
				A basic webserver to serve out files
				},
			'Author'      => 
				[
					'sussurro',
				],
			'License'     => BSD_LICENSE,
			'Actions'     =>
				[
					[ 'WebServer', {
						'Description' => 'Launch the webserver' 
					} ]
				],
			'PassiveActions' => 
				[ 'WebServer' ],
			'DefaultAction'  => 'WebServer'))

		register_options([
                                OptString.new('WEBROOT', [ true, 'The location of the exploits directory.', File.join(Msf::Config.install_root, 'data', 'exploits')]),
                                OptBool.new('ALLOWINDEX', [ false, 'Allow indexes to be displayed.', false]),

		], self.class)

	end


	def run
			exploit()
	end



	def on_request_uri(cli, request) 

		print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

		filename = request.uri.gsub(/^#{self.get_resource}/,'')
                path = ::File.join(datastore['WEBROOT'], filename)
		print_status("Request translates to #{path}")
                if(not ::File.exists?(path))
			print_status("404ing #{request.uri}")
			send_not_found(cli)
			return false
                end
		if(::File.directory?(path) and datastore['ALLOWINDEX'])
			html = "<HTML><BODY>\n"
			html += "<A HREF=\"#{request.uri}/..\">[..]</A><BR>\n"
			::Dir.entries(path).each do |file|
				next if(file.starts_with?'.')
				if(::File.directory?(::File.join(path,file)))
					if(request.uri.ends_with?"/")
						html += "<A HREF=\"#{request.uri}#{file}\">[#{file}]</A><BR>\n"
					else
						html += "<A HREF=\"#{request.uri}/#{file}\">[#{file}]</A><BR>\n"
					end
				else
					html += "<A HREF=\"#{request.uri}/#{file}\">#{file}</A><BR>\n"
				end
			end
			html += "</BODY></HTML>\n"
                        response = create_response()
                        response["Expires"] = "0"
                        response["Cache-Control"] = "must-revalidate"
                        response.body = html
                        cli.send_response(response)
			return
		elsif(::File.directory?(path))
			print_status("404ing #{request.uri}")
			send_not_found(cli)
			return false
		else
			data = ::File.read(path, ::File.size(path))
                	send_response(cli, data, { 'Content-Type' => 'application/octet-stream' })
			print_status("Data file #{path} delivered to #{cli.peerhost}")

			return 
		end

	end

end

