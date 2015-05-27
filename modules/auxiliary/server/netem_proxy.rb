##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'vagrant-wrapper'

class Metasploit3 < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Emulate network conditions via a proxy router',
        'Description' =>
        %q(
            This module will enable a local proxy router that can emulate bad
            network conditions. Traffic forwarded through the router to or from
            the local host can emulate network bandwidth, latency and packet loss
            conditions.
          ),
        'License'     => MSF_LICENSE,
        'Author'      => ['bcook']
      )
    )

    name = 'metasploit_netem_router'

    register_options(
      [
        OptInt.new("PacketDelayMs",          [false, 'Packet delay in ms', 0]),
        OptInt.new("PacketLossPercent",      [false, 'Packet loss percentage', 0]),
        OptInt.new("PacketDupPercent",       [false, 'Packet dup percentage', 0]),
        OptInt.new("PacketCorruptPercent",   [false, 'Packet corruption percentage', 0]),
        OptInt.new("NetworkOutageInterval",  [false, 'Period in seconds to simulate network outages', 0]),
        OptInt.new("NetworkOutageDuration",  [false, 'Length in seconds of network outages', 30]),

        OptString.new('VagrantName',    [true, 'Vagrant image name', name]),
        OptString.new('VagrantBox',     [true, 'Vagrant box for the router VM', 'ubuntu/trusty64']),
        OptString.new('VagrantNet',     [true, 'Vagrant private network', '192.168.13.2']),
        OptEnum.new('VagrantCleanup',   [true, 'Cleanup method', 'suspend', ['suspend', 'destroy', 'none']]),

        OptString.new('SRVHOST',      [false, 'The address to listen on', '']),
        OptPort.new('SRVPORT',        [true,  'The port to listen on', 4445]),
        OptEnum.new('SRVPROTO',       [true,  'The protocol to use', 'tcp', ['udp', 'tcp']]),
        OptString.new('LHOST',        [true,  'The address to forward to', '192.168.13.1']),
        OptPort.new('LPORT',          [true,  'The port to forward to', 4444])
      ], self.class)
  end

  def vagrant_image_name
    "Vagrant image #{datastore['VagrantName']} (#{datastore['VagrantBox']})"
  end

  def vagrant_create_environment
    @vagrant_dir = File.join(Dir.tmpdir, datastore['VagrantName'])
    @vagrant_file = File.join(@vagrant_dir, 'Vagrantfile')
    @vagrant_cleanup = datastore['VagrantCleanup']
    @net_outage_interval = datastore['NetworkOutageInterval']
    @net_outage_duration = datastore['NetworkOutageDuration']
    ENV['VAGRANT_CWD'] = @vagrant_dir
  end

  def gen_linux_routing_cmds(pub_intf, priv_intf)
    routing_cmds = []

    [pub_intf, priv_intf].each do |intf|
      routing_cmds << "sysctl -w net.ipv4.conf.#{intf}.forwarding=1"
      routing_cmds << "sysctl -w net.ipv6.conf.#{intf}.forwarding=1"
    end

    routing_cmds << "iptables -t nat -F"
    routing_cmds << "iptables -t nat -A PREROUTING -i #{pub_intf} -p #{datastore['SRVPROTO']}" \
                    " --dport #{datastore['SRVPORT']} -j DNAT" \
                    " --to-destination #{datastore['LHOST']}:#{datastore['LPORT']}"
    routing_cmds << "iptables -t nat -A POSTROUTING -j MASQUERADE"

    tc_opts = []
    tc_opts << "delay #{datastore['PacketDelayMs']}ms" if datastore['PacketDelayMs'] > 0
    tc_opts << "loss #{datastore['PacketLossPercent']}%" if datastore['PacketLossPercent'] > 0.0
    tc_opts << "duplicate #{datastore['PacketDupPercent']}%" if datastore['PacketDupPercent'] > 0.0
    tc_opts << "corrupt #{datastore['PacketCorruptPercent']}%" if datastore['PacketCorruptPercent'] > 0.0

    routing_cmds << "tc qdisc delete dev #{priv_intf} root || true"
    unless tc_opts.empty?
      tc_opt = tc_opts.join(" ")
      routing_cmds << "tc qdisc add dev #{priv_intf} root netem #{tc_opt}"
    end

    routing_cmds
  end

  def vagrant_write_config
    port_forward = [':forwarded_port']
    port_forward << "guest: #{datastore['SRVPORT']}"
    port_forward << "host: #{datastore['SRVPORT']}"
    port_forward << "proto: \"#{datastore['SRVPROTO']}\""
    if datastore['SRVHOST'] != ""
      port_forward << "host_ip: datastore['SRVHOST']"
    end

    provision_cmds = []
    gen_linux_routing_cmds('eth0', 'eth1').each do |cmd|
      provision_cmds << "os.vm.provision \"shell\", inline: \"#{cmd}\""
    end

    vagrant_tpl = %{
VAGRANTFILE_API_VERSION = "2"
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.provision "fix-no-tty", type: "shell" do |s|
    s.privileged = false
    s.inline = "sudo sed -i '/tty/!s/mesg n/tty -s \\&\\& mesg n/' /root/.profile"
  end
  config.vm.define "#{datastore['VagrantName']}" do |os|
    os.vm.box = "#{datastore['VagrantBox']}"
    os.vm.network #{port_forward.join(', ')}
    os.vm.network :private_network, ip: "#{datastore['VagrantNet']}"
    os.vm.provision "shell", inline: "apt-get install -y conntrack"
    #{provision_cmds.join("\n    ")}
  end
end
    }

    Dir.mkdir(@vagrant_dir, 0700) unless Dir.exist?(@vagrant_dir)
    File.open(@vagrant_file, 'w') { |file| file.write(vagrant_tpl) }
  end

  def cleanup_vm(_obj)
    # Cleanup the VM
    case @vagrant_cleanup
    when 'destroy'
      print_status("Destroying #{vagrant_image_name}")
      @vagrant.get_output('destroy -f')
    when 'suspend'
      print_status("Suspending #{vagrant_image_name}")
      @vagrant.get_output('suspend')
    end
  end

  def monitor_vm(_obj)
    # Sleep while waiting for the job to be killed
    last_outage = 0
    loop do
      sleep 1
      last_outage += 1
      if @net_outage_interval > 0 && last_outage >= @net_outage_interval
        print_status("Starting network outage on #{vagrant_image_name}")
        @vagrant.get_output('ssh -c "sudo ip link set eth1 down"')
        sleep @net_outage_duration
        print_status("Ending network outage on #{vagrant_image_name}")
        @vagrant.get_output('ssh -c "sudo ip link set eth1 up"')
        last_outage = 0
      end
    end
  end

  def run
    # Handle check for vagrant
    begin
      @vagrant = VagrantWrapper.new('> 1.5')
    rescue ::Exception => e
      print_error(e.message)
      print_status(install_instructions)
      return
    end

    # Spinup the VM
    vagrant_create_environment
    vagrant_write_config

    print_status("Starting #{vagrant_image_name}")
    @vagrant.get_output('up')
    @vagrant.get_output('provision')
    print_status("Vagrant router image started")

    framework.jobs.start_bg_job(
      "Auxiliary: #{refname}",
      self,
      proc { |ctx_| monitor_vm(ctx_) },
      proc { |ctx_| cleanup_vm(ctx_) }
    )
  end
end
