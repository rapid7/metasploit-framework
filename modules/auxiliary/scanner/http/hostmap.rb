require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::WmapScanServer

	def initialize(info = {})
		super(update_info(info,	
			'Name'		=> 'HOSTMAP Virtual Host Discovery Module',
			'Description'	=> %q{
				Hostmap is a free, automatic, hostnames and virtual hosts discovery
				tool. It's goal is to enumerate all hostnames and configured virtual
				hosts on an IP address. The primary users of hostmap are professionals 
				performing vulnerability assessments and penetration tests.
			},
			'Author'	=>
				[
					'Alessandro Tanasi <alessandro[at]tanasi.it>',
					'Aram Verstegen <aram.verstegen[at]gmail.com>',
				],
			'License'	=> MSF_LICENSE,
			'Version'	=> '$Revision$',
			'References'	=>
				[
					['URL', 'http://hostmap.lonerunners.net'],
				]
			))

		register_options(
			[
				OptString.new('OPTS', [ false, "The hostmap options to use", '' ]),
				OptPath.new('HOSTMAP_PATH', [ true, "The hostmap >= 0.2.1 full path ", '/hostmap/hostmap.rb' ]), 
			], self.class)
		register_advanced_options(
			[
				OptBool.new('BRUTE_FORCING', [ true, "Enables DNS names brute forcing", true ]),
			], self.class)
	end

	# Test a single host
	def run_host(ip)
		hostmap = File.join(datastore['HOSTMAP_PATH'], 'hostmap.rb')
		if not File.file?(hostmap)
			print_error("The hostmap script could not be found")
			return
		end

		wmap_target_host = datastore['RHOST'] || ip
		target = Resolv.getaddress(wmap_target_host)
		host = self.framework.db.workspace.hosts.find_or_create_by_address(target)
		service_ports = host.services.find(:all, :conditions => {:proto => 'tcp', :name => ['http', 'https']})
		if service_ports.empty?
			# If no web services have been found yet, try to find common web wervice ports
			service_ports = host.services.find(:all, :conditions => {:proto => 'tcp', :port => [80, 8080, 443]})
			if service_ports.empty?
				# If no website has been found yet, create a dummy website to associate vhosts to
				print_status "Adding a dummy HTTP service at port 80 to associate vhosts to as no HTTP services were found"
				service_ports = [host.services.create(:proto => 'tcp', :port => 80, :name => 'http')]
			end
		end

		print_status "Starting Hostmap scan on #{target} - aware of HTTP on ports #{service_ports.map{|x| x.port}}"
		cmd = [ hostmap, datastore['OPTS'] ]
		cmd << '--without-bruteforce' if not datastore['BRUTE_FORCING'] 
		cmd += [ '-t', target ]

		print_status("Running: #{cmd.join(' ')} (please wait)")
		handle = IO.popen(cmd)
		lines = handle.readlines
		lines.each do |line|
			if line =~ /Found new hostname/
				hostname = line.split('Found new hostname ')[1].strip
				if not host.web_sites.find_by_vhost(hostname)
					service_ports.each do |service|
						vhost = service.web_sites.find_or_create_by_vhost(hostname)
						vhost.service.host = host
						vhost.save
					end
				end
				print_status "Found and added hostname #{hostname}"
			end
		end
	end

end

