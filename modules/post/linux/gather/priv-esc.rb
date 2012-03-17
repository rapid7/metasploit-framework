require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'
require 'msf/core/post/linux/priv'
require 'yaml'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Check for Linux Kernel Privilege Escalations',
				'Description'   => %q{
					This module does stuff
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'ohdae <bindshell[at]live.com>',
						'kernelsmith <kernelsmith /x40 kernelsmith /x2E com>'
					],
				'Version'       => '$Revision$',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))
		@ref_file = ::File.join(Msf::Config.install_root, "data", "localprivesc.yml")
		register_options(
			[
				OptPath.new('REF_FILE', [true, 'Reference yml file from which to get the exploit info',@ref_file])
			], self.class)
			
	end

	def run

		info = get_sysinfo
		kernel = info[:kernel]
		
#		store_loot(
#			"linux.version",
#			"text/plain",
#			session,
#			"Distro: #{distro[:distro]},Version: #{distro[:version]}, Kernel: #{distro[:kernel]}",
#			"linux_info.txt",
#			"Linux Version")

		# Print the info
		print_good("Info:")
		print_good("\t#{info[:version]}")
		print_good("\t#{kernel}")

		# clean up kernel so it's just the version info
		# turns out, it's actually easier to just run our own uname (rather than parse get_sysinfo), 
		# and clean that up
		kernel_ver = cleanup_kernel_version(session.shell_command_token("uname -r").chomp)
		#kernel_ver = cleanup_kernel_version("2.4.1") # <--- for testing

    	print_status "Checking for exploits for local kernel version #{kernel_ver}"
		poss_exploits = check_for_exploits(kernel_ver)
		if ! poss_exploits.empty?
    		print_status "Possible exploits that might work:\n"
			# A table to display findings
			exploit_table = Rex::Ui::Text::Table.new(
				'Header'    => "Possible Exploits",
				'Indent'    => 1,
				'Columns'   =>[
					"Name",
					"CVE",
					"Versions Affected",
					"Exploit-db No. or other URL"
				])
    		poss_exploits.each do |e|
    			exploit_table << [e["name"],e["cve"],e["versions"],e["exploits"]]
    		end
    		print_line exploit_table.to_s
		else
			print_status "Nothing found"
		end
	end
	
	def check_for_exploits(kernel)
    	found_exploits = []

    	exploits = YAML::load_file(datastore["REF_FILE"])
    	exploits.each do |h|
    	    h["versions"].each do |version_range|
	            if check_version(kernel,version_range)
    	            found_exploits << h
    	        end
    	    end
    	end
    	return found_exploits
	end
	
	def cleanup_kernel_version(kernel_ver)
		# to get rid of trailing letters like -server
		kernel_ver.split(/-*([a-zA-Z]+)$/).first
		# TODO:  are there any possible prefixed letters?
	end
	
	def check_version(kernel,version_range)
		#print_good "Comparing #{kernel} against the range #{version_range}"
		# we assume the kernel version has been cleaned up, handle your bidness
		# now we convert all the parts of the version to integer so we can properly compare
		min,max = version_range.split("-") # if no "-" found, max becomes nil
		max = min unless max # make the max same as the min if no range was given
		min_arr = convert_to_int_array(min)
		max_arr = convert_to_int_array(max)
		kernel_arr = convert_to_int_array(kernel)
		# now do the actual comparison, comparing each part of the version as an integer
		good_version = true
		kernel_arr.each_with_index do |item,idx|
			# TODO:  What to do if array lengths don't match like 2.4.0.4 against 2.4.0-2.4.22
			# for now let's punt and call that a success and stop comparing
			break if min_arr[idx].nil? or max_arr[idx].nil?
			good_version = false if item < min_arr[idx] or item > max_arr[idx]
			break unless good_version
		end
		good_version
	end
	
	def convert_to_int_array(kernel_ver)
		#print_good "Converting #{kernel_ver} to an int array"
		arr = kernel_ver.split(".")
		#TODO:  What to do with input like 2.6.32-30, for now, just keep the first part (32)
		arr.each_with_index do |item,idx|
			arr[idx] = item.split("-").first.to_i
		end
		#print_good "Array is #{arr.inspect}"
		arr
	end
end

