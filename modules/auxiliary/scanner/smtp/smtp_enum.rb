##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Smtp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'SMTP User Enumeration Utility',
			'Description' => %q{
				The SMTP service has two internal commands that allow the enumeration
				of users: VRFY (confirming the names of valid users) and EXPN (which
				reveals the actual address of users aliases and lists of e-mail
				(mailing lists)). Through the implementation of these SMTP commands can
				reveal a list of valid users.
				},
			'References'  =>
			[
				['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
				['OSVDB', '12551'],
				['CVE', '1999-0531']
			],
				'Author'      =>
			[
				'==[ Alligator Security Team ]==',
				'Heyder Andrade <heyder[at]alligatorteam.org>'
			],
				'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(25),
				OptString.new('USER_FILE',
					[
						true, 'The file that contains a list of probable users accounts.',
						File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
					]
				)], self.class)

		deregister_options('MAILTO','MAILFROM')
	end

	def target
		"#{rhost}:#{rport}"
	end

	def smtp_send(data=nil, con=true)
		begin
			@result=''
			@coderesult=''
			if (con)
				@connected=false
				connect
				select(nil,nil,nil,0.4)
			end
			@connected=true
			sock.put("#{data}")
			@result=sock.get_once
			@coderesult=@result[0..2] if @result
		rescue ::Exception => e
			print_error("Error: #{e}")
			raise e
		end
	end

	def run_host(ip)
		@users_found = {}
		@mails_found = {}
		cmd = 'HELO' + " " + "localhost" + "\r\n"
		smtp_send(cmd,true)
		print_status(banner)
		@domain = @result.split()[1].split(".")[1..-1].join(".")
		print_status("Domain Name: #{@domain}")

		begin
			cmd = 'VRFY' + " " + "root" + "\r\n"
			smtp_send(cmd,!@connected)
			if (@result.match(%r{Cannot})) or (@result.match(%r{recognized}))
				vprint_status("VRFY command disabled")
			elsif (@result.match(%r{restricted}))
				vprint_status("VRFY command restricted")
			else
				vprint_status("VRFY command enabled")
				vrfy_ok=true
			end
		end

		begin
			if (vrfy_ok)
				extract_words(datastore['USER_FILE']).each {|user|
					do_vrfy_enum(user)
				}
			else
				do_mail_from()
				extract_words(datastore['USER_FILE']).each {|user|
					return finish_host() if ((do_rcpt_enum(user)) == :abort)
				}
			end

			if(@users_found.empty?)
				print_status("#{target} No users or e-mail addresses found.")
			else
				vprint_status("#{target} - SMTP - Trying to get valid e-mail addresses")
				@users_found.keys.each {|mails|
					return finish_host() if((do_get_mails(mails)) == :abort)
				}
				finish_host()
				disconnect
			end
		end
	end

	def finish_host()
		if @users_found && !@users_found.empty?
			print_good("#{target} Users found: #{@users_found.keys.sort.join(", ")}")
			report_note(
				:host => rhost,
				:port => rport,
				:type => 'smtp.users',
				:data => {:users =>  @users_found.keys.join(", ")}
			)
		end

		if(@mails_found.nil? or @mails_found.empty?)
			print_status("#{target} No e-mail addresses found.")
		else
			print_good("#{target} E-mail addresses found: #{@mails_found.keys.sort.join(", ")}")
			report_note(
				:host => rhost,
				:port => rport,
				:type => 'smtp.mails',
				:data => {:mails =>  @mails_found.keys.join(", ")}
			)
		end
	end

	def do_vrfy_enum(user)
		cmd = 'VRFY' + " " + user + "\r\n"
		smtp_send(cmd,!@connected)
		vprint_status("#{target} - SMTP - Trying name: '#{user}'")
		case @coderesult.to_i
		when (250..259)
			print_good "#{target} - Found user: #{user}"
			@users_found[user] = :reported
			mail = @result.scan(%r{\<(.*)(@)(.*)\>})
			unless (mail.nil? || mail.empty?)
				@mails_found[mail.to_s] = :reported
			end
		end
	end

	def do_mail_from()
		vprint_status("Trying to use to RCPT TO command")
		cmd = 'MAIL FROM:' + " root@" + @domain + "\r\n"
		smtp_send(cmd,!@connected)
		if (@coderesult == '501') && @domain.split(".").count > 2
			print_error "#{target} - MX domain failure for #{@domain}, trying #{@domain.split(/\./).slice(-2,2).join(".")}"
			cmd = 'MAIL FROM:' + " root@" + @domain.split(/\./).slice(-2,2).join(".") + "\r\n"
			smtp_send(cmd,!@connected)
			if (@coderesult == '501')
				print_error "#{target} - MX domain failure for #{@domain.split(/\./).slice(-2,2).join(".")}"
				return :abort
			end
		elsif (@coderesult == '501')
			print_error "#{target} - MX domain failure for #{@domain}"
			return :abort
		end
	end

	def do_rcpt_enum(user)
		cmd = 'RCPT TO:' + " " + user + "\r\n"
		smtp_send(cmd,!@connected)
		vprint_status("#{target} - SMTP - Trying name: '#{user}'")
		case @coderesult.to_i
		# 550 is User unknown, which obviously isn't fatal when trying to
		# enumerate users, so only abort on other 500-series errors.  See #4031
		when (500..549), (551..599)
			print_error "#{target} : #{@result.strip if @result} "
			print_error "#{target} : Enumeration not possible"
			return :abort
		when (250..259)
			print_good "#{target} - Found user: #{user}"
			@users_found[user] = :reported
			mail = @result.scan(%r{\<(.*)(@)(.*)\>})
			unless (mail.nil? || mail.empty?)
				@mails_found[mail.to_s] = :reported
			end
		end
	end

	def do_get_mails(user)
		cmd = 'EXPN' + " " + user + "\r\n"
		smtp_send(cmd,!@connected)
		if (@coderesult == '502')
			print_error "#{target} - EXPN : #{@result.strip if @result}"
			return :abort
		else
			unless (@result.nil? || @result.empty?)
				mail = @result.scan(%r{\<(.*)(@)(.*)\>})
				unless (mail.nil? || mail.empty?)
					print_good "#{target} - Mail Found: #{mail}"
					@mails_found[mail.to_s] = :reported
				end
			end
		end
	end

	def extract_words(wordfile)
		return [] unless wordfile && File.readable?(wordfile)
		begin
			words = File.open(wordfile, "rb") {|f| f.read}
		rescue
			return
		end
		save_array = words.split(/\r?\n/)
		return save_array
	end

end
