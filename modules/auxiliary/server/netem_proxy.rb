##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'vagrant-wrapper'

class Metasploit3 < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Emulate network conditions via a proxy router',
      'Description'    => %q{
          This module will enable a local proxy router that can emulate bad
          network conditions. Traffic forwarded through the router to or from
          the local host can emulate network bandwidth, latency and packet loss
          conditions.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['bcook'],
    ))

    name = 'metasploit_netem_router'

    register_options(
      [
        OptInt.new("PacketDelay",     [false, 'Packet delay in ms', 0]),
        OptString.new("DataRate",     [false, 'Data rate in Mbps (0 is unlimited)', 0.0]),
        OptInt.new("PacketLoss",      [false, 'Packet loss percentage', 0.0]),
        OptInt.new("PacketDup",       [false, 'Packet dup percentage', 0.0]),
        OptInt.new("PacketCorrupt",   [false, 'Packet corruption percentage', 0.0]),

        OptString.new('VagrantName',  [true,  'Vagrant image name', name]),
        OptString.new('VagrantBox',   [true,  'Vagrant box for the router VM', 'ubuntu/trusty64']),
        OptString.new('VagrantNet',   [true,  'Vagrant private network', '192.168.13.2']),
        OptBool.new('VagrantDestroy', [true,  'Destroy image on stop', false]),

        OptString.new('SRVHOST',      [false, 'The address to listen on', '']),
        OptPort.new('SRVPORT',        [true,  'The port to listen on', 4445]),
        OptEnum.new('SRVPROTO',       [true,  'The protocol to use', 'tcp', ['udp', 'tcp']]),
        OptString.new('LHOST',        [true,  'The address to forward to', '192.168.13.1']),
        OptPort.new('LPORT',          [true,  'The port to forward to', 4444]),
      ], self.class)

  end

  def vagrant_image_name
    "Vagrant image #{datastore['VagrantName']} (#{datastore['VagrantBox']})"
  end

  def vagrant_create_environment
    @vagrant_dir = File.join(Dir.tmpdir, datastore['VagrantName'])
    @vagrant_file = File.join(@vagrant_dir, 'Vagrantfile')
    @vagrant_destroy = datastore['VagrantDestroy']
    ENV['VAGRANT_CWD'] = @vagrant_dir
  end

  def gen_linux_routing_cmds(pub_intf, priv_intf)
    routing_cmds = []

    [pub_intf, priv_intf].each do |intf|
      routing_cmds << "sysctl -w net.ipv4.conf.#{intf}.forwarding=1"
      routing_cmds << "sysctl -w net.ipv6.conf.#{intf}.forwarding=1"
    end

    routing_cmds << "iptables -t nat -F"
    routing_cmds << "iptables -t nat -A PREROUTING -i #{pub_intf} -p #{datastore['SRVPROTO']}" +
                    " --dport #{datastore['SRVPORT']} -j DNAT" +
                    " --to-destination #{datastore['LHOST']}:#{datastore['LPORT']}"
    routing_cmds << "iptables -t nat -A POSTROUTING -j MASQUERADE"

    tc_opts = []
    tc_opts << "delay #{datastore['PacketDelay']}ms" if datastore['PacketDelay'] > 0
    tc_opts << "loss #{datastore['PacketLoss']}%" if datastore['PacketLoss'] > 0.0
    tc_opts << "duplicate #{datastore['PacketDup']}%" if datastore['PacketDup'] > 0.0
    tc_opts << "corrupt #{datastore['PacketCorrupt']}%" if datastore['PacketCorrupt'] > 0.0

    routing_cmds << "tc qdisc delete dev #{priv_intf} root"
    if !tc_opts.empty?
      tc_opt = tc_opts.join(" ")
      routing_cmds << "tc qdisc add dev #{priv_intf} root netem #{tc_opt}"
    end

    kbps = datastore['DataRate'] * 1000
    if kbps > 0.0
      #routing_cmds << "tc class add dev #{priv_intf} parent 1:1 handle 10 htb rate #{kbps}Kbps"
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

    vagrant_tpl = %Q{
VAGRANTFILE_API_VERSION = "2"
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "#{datastore['VagrantName']}" do |os|
    os.vm.box = "#{datastore['VagrantBox']}"
    os.vm.network #{port_forward.join(', ')}
    os.vm.network :private_network, ip: "#{datastore['VagrantNet']}"
    #{provision_cmds.join("\n    ")}
  end
end
    }

    Dir.mkdir(@vagrant_dir, 0700) if !Dir.exist?(@vagrant_dir)
    File.open(@vagrant_file, 'w') { |file| file.write(vagrant_tpl) }
  end

  def cleanup_vm(obj)
    # Cleanup the VM
    if @vagrant_destroy
      print_status("Destroying #{vagrant_image_name}")
      @vagrant.get_output('destroy -f')
    else
      print_status("Suspending #{vagrant_image_name}")
      @vagrant.get_output('suspend')
    end
  end

  def monitor_vm(obj)
    # Sleep while waiting for the job to be killed
    while true
      sleep 10
    end
  end

  def run
    # Handle check for vagrant
    begin
      @vagrant = VagrantWrapper.new('> 1.5')
    rescue ::Exception => e
      print_error(e.message)
      print_status(VagrantWrapper::install_instructions)
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
      "Auxiliary: #{self.refname}",
      self,
      Proc.new { |ctx_| self.monitor_vm(ctx_) },
      Proc.new { |ctx_| self.cleanup_vm(ctx_) }
    )
  end
end
