
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require "net/dns/resolver"

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Smtp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'SMTP Open Relay Server Detection',
			'Version'     => '$Revision: $',
			'Description' => 'Checks if a SMTP server is an open relay.',
			'References'  =>
				[
					['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
					['URL', 'http://en.wikipedia.org/wiki/Open_mail_relay'],
					['URL', 'http://www.abuse.net/relay.html'],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		))

		register_options(
			[
				OptString.new('DOMAIN', [ true, "The target domain name"]),
				OptAddress.new('NS', [ false, "Specify the nameserver to use for queries, otherwise use the system DNS" ]),
				OptInt.new('DELAY_INTERVAL', [ false, "Number of seconds to wait before doing a test", false]),
			], self.class)

		deregister_options('MAILFROM','MAILTO','RHOST','RHOSTS','RPORT')
	end

	# Get the authoritative DNS server
	def switchdns(target)
		if not datastore['NS'].nil?
			print_status("Using DNS Server: #{datastore['NS']}")
			@res.nameserver = (datastore['NS'])
		else
			querysoa = @res.query(target, "SOA")
			if (querysoa)
				(querysoa.answer.select { |i| i.class == Net::DNS::RR::SOA}).each do |rr|
					query1soa = @res.search(rr.mname)
					if (query1soa and query1soa.answer[0])
						@res.nameserver = (query1soa.answer[0].address)
					end
				end
			end
		end
	end

	# Get MX reverse address necessary in spam_addresses
	def reverse_lookup(target)
		query = @res.query(target, "A")
		if query.answer.length != 0
			query.answer.each do |rr|
				if (rr.class != Net::DNS::RR::CNAME)
					return rr.address.to_s
				end
			end
		else
			return '127.0.0.1'
		end
	end

	# Get MX record for a domain; tnx to 'auxiliary/gather/dns_enum'
	def get_mx(target)
		query = @res.query(target, "MX")
		if (query)
			(query.answer.select { |i| i.class == Net::DNS::RR::MX}).each do |rr|
				return rr.exchange.chop
			end
		end
	end

	# Send SMTP requests; tnx to 'auxiliary/scanner/smtp/smtp_enum'
	def smtp_send(data=nil, con=true)
		begin
			@result = ''
			@coderesult = ''
			if (con)
				@connected = false
				connect
				select(nil, nil, nil, 0.4)
			end
			@connected = true
			sock.put("#{data}")
			@result = sock.get_once
			@coderesult = @result[0..2] if @result
		rescue ::Interrupt
			raise $!
		rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused, ::IOError
		rescue ::Exception => e
			print_error("Unknown error: #{e.class} #{e}")
		end
	end

	def run
		target = datastore['DOMAIN']

		@res = Net::DNS::Resolver.new()

		# Get the authoritative DNS server
		switchdns(target)
		print_status("Authoritative DNS server for #{target} is #{@res.nameserver}")

		# Get MX record
		mx = get_mx(target)

		if not mx.nil? and not mx.empty?

			datastore['RHOST'] = mx.to_s
			datastore['RPORT'] = 25

			print_status("Mail server for #{target} is #{mx}")

			mail_from = Rex::Text.rand_mail_address
			print_status("Random email generated : #{mail_from}")

			# Stuff for spam_addresses
			mail_from_name,mail_from_domain = mail_from.split("\@")
			rev_address = reverse_lookup(mx)

			# Random fake hostname for HELO
			hostname = Rex::Text.rand_hostname
			print_status("Random hostname generated : #{hostname}")

			# Get SMTP server banner
			cmd = 'HELO' + ' ' + hostname + "\r\n"
			smtp_send(cmd,!@connected)

			if not @coderesult.nil? and not @coderesult.empty?
				if @coderesult.to_i == 250
					print_good("Mail server banner : #{banner.chop}")
					report_service(
						:host => datastore['RHOST'],
						:port => datastore['RPORT'],
						:name => "smtp",
						:info => banner.chop
					)
				else
					print_error("#{@result.strip if @result} ")
				end
			end

			# Mail relay tests
			# http://www.abuse.net/relay.html
			spam_addresses = [
				{ "" => "#{mail_from}" },
				{ "spamtest" => "#{mail_from}" },
				{ "spamtest@#{mail_from_domain}" => "#{mail_from}" },
				{ "spamtest@#{target}" => "#{mail_from}" },
				{ "spamtest@[#{rev_address}]" => "#{mail_from}" },
				{ "spamtest@#{target}" => "#{mail_from_name}%#{mail_from_domain}@#{target}" },
				{ "spamtest@#{target}" => "#{mail_from_name}%#{mail_from_domain}@[#{rev_address}]" },
				{ "spamtest@#{target}" => "\"#{mail_from_name}@#{mail_from_domain}\"" },
				{ "spamtest@#{target}" => "\"#{mail_from_name}%#{mail_from_domain}\"" },
				{ "spamtest@#{target}" => "#{mail_from}@#{target}" },
				{ "spamtest@#{target}" => "\"#{mail_from}\"@#{target}" },
				{ "spamtest@#{target}" => "#{mail_from}@[#{rev_address}]" },
				{ "spamtest@#{target}" => "@#{target}:#{mail_from}" },
				{ "spamtest@#{target}" => "@[#{rev_address}]:#{mail_from}" },
				{ "spamtest@#{target}" => "#{mail_from_domain}!#{mail_from_name}" },
				{ "spamtest@#{target}" => "#{mail_from_domain}!#{mail_from_name}@#{target}" },
				{ "spamtest@#{target}" => "#{mail_from_domain}!#{mail_from_name}@[#{rev_address}]" },
			]

			# RESET (RSET)
			# This command specifies that the current mail transaction is to be aborted.
			# Any stored sender, recipients, and mail data must be discarded, and all
			# buffers and state tables cleared. The receiver must send an OK reply.
			cmd = 'RSET' + "\r\n"
			smtp_send(cmd,!@connected)

			if not @coderesult.nil? and not @coderesult.empty?

				# We use RESET also to check for a valid connection to mail server
				if @coderesult.to_i == 250

					n = 1
					spam_addresses.each do |c|
						c.each do |key, value|

							if datastore['DELAY_INTERVAL'].to_i > 0
								print_status("Waiting #{datastore['DELAY_INTERVAL'].to_i} seconds...")
								select(nil, nil, nil, datastore['DELAY_INTERVAL'].to_i)
							else
								select(nil, nil, nil, 1)
							end

							print_status("Relay test #{n}")

							cmd = 'RSET' + "\r\n"
							smtp_send(cmd,true)

							print_status(" MAIL FROM:<#{key}>")
							cmd = 'MAIL FROM:' + ' ' + '<' + key + '>' + "\r\n"
							smtp_send(cmd,!@connected)

							if @coderesult.to_i == 0
								next
							end

							print_status(" RCPT TO:<#{value}>")
							cmd = 'RCPT TO:' + ' ' + '<' + value + '>' + "\r\n"
							smtp_send(cmd,!@connected)

							if not @coderesult.nil? and not @coderesult.empty?
								if @coderesult.to_i == 250
									print_good(" Relay permitted!")
									report_service(
										:host => datastore['RHOST'],
										:port => datastore['RPORT'],
										:name => "smtp open relay",
										:info => "#{target};mail_from=<#{key}>;rcpt_to=<#{value}>"
									)
								else
									print_error(" #{@result.strip if @result} ")
								end
							end

							cmd = 'QUIT' + "\r\n"
							smtp_send(cmd,!@connected)
						end
						n += 1
					end
				else
					print_error("#{@result.strip if @result} ")
				end
			else
				print_error("Error: unable to connect to remote host.")
			end
		else
			print_error("Error: unable to resolve the MX record for #{target}.")
		end
	end
end
