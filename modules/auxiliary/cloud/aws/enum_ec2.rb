##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'aws-sdk-ec2'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Amazon Web Services EC2 instance enumeration',
        'Description' => %q{
          Provided AWS credentials, this module will call the authenticated
          API of Amazon Web Services to list all EC2 instances associated
          with the account
        },
        'Author' => [
          'Aaron Soto <aaron.soto@rapid7.com>',
          'RageLtMan <rageltman[at]sempervictus>'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS],
          'Stability' => [CRASH_SAFE],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptInt.new('LIMIT', [false, 'Only return the specified number of results from each region']),
        OptString.new('REGION', [false, 'AWS Region (eg. "us-west-2")']),
        OptString.new('ACCESS_KEY_ID', [true, 'AWS Access Key ID (eg. "AKIAXXXXXXXXXXXXXXXX")', '']),
        OptString.new('SECRET_ACCESS_KEY', [true, 'AWS Secret Access Key (eg. "CA1+XXXXXXXXXXXXXXXXXXXXXX6aYDHHCBuLuV79")', ''])
      ]
    )
  end

  def enumerate_regions
    regions = []

    ec2 = Aws::EC2::Resource.new(
      region: 'us-west-1',
      access_key_id: datastore['ACCESS_KEY_ID'],
      secret_access_key: datastore['SECRET_ACCESS_KEY']
    )

    ec2_regions = ec2.client.describe_regions.data.regions
    ec2_regions.each do |r|
      regions.append(r.region_name)
    end

    regions
  end

  def describe_ec2_instance(inst)
    print_good "  #{inst.id} (#{inst.state.name})"
    print_good "    Creation Date:  #{inst.launch_time}"
    print_good "    Public IP:      #{inst.public_ip_address} (#{inst.public_dns_name})"
    print_good "    Private IP:     #{inst.private_ip_address} (#{inst.private_dns_name})"
    # Report hosts and info
    mac_addr = inst.network_interfaces.select do |iface|
      iface.private_ip_address == inst.private_ip_address
    end.first.mac_address
    iname = inst.tags.find { |t| t.key == 'Name' } ? inst.tags.find { |t| t.key == 'Name' }.value : inst.private_dns_name
    iinfo = inst.tags.find { |t| t.key == 'Description' } ? inst.tags.find { |t| t.key == 'Description' }.value : nil
    report_host(
      host: inst.private_ip_address,
      mac: mac_addr,
      os_name: inst.platform_details,
      os_flavor: inst.architecture,
      name: iname,
      info: iinfo,
      comments: "ec2-id: #{inst.id} (#{inst.placement.availability_zone})"
    )
    if inst.public_ip_address
      report_note(
        host: inst.private_ip_address,
        type: 'ec2.public_ip',
        data: { :public_ip_address => inst.public_ip_address }
      )
    end
    # eips = inst.network_interfaces.map {|i| i.association && i.association.public_ip}.compact # <-- works in pry, breaks at runtime in AWS SDK
    # report_note(
    #  host: inst.private_ip_address,
    #  type: 'ec2.public_ips',
    #  data: { :eips => eips.join(' ') }
    # ) unless eips.empty?
    if inst.public_ip_address && !inst.public_dns_name.empty?
      report_note(
        host: inst.private_ip_address,
        type: 'ec2.public_dns',
        data: {
          :public_dns_name => inst.public_dns_name,
          :public_ip_address => inst.public_ip_address
        }
      )
    end
    if inst.hypervisor
      report_note(
        host: inst.private_ip_address,
        type: 'ec2.hypervisor',
        data: { :hypervisor => inst.hypervisor }
      )
    end
    inst.security_groups.each do |s|
      print_good "    Security Group: #{s.group_id}"
      report_note(
        host: inst.private_ip_address,
        type: "ec2.#{s.group_id}",
        data: { :group_name => s.group_name }
      )
    end
    inst.tags.each do |t|
      print_good "    Tag: #{t.key} = #{t.value}"
      report_note(
        host: inst.private_ip_address,
        type: "ec2.tag #{t.key}",
        data: { :tag => t.value }
      )
    end
  end

  def run
    all_regions = enumerate_regions
    if datastore['REGION'].blank?
      regions = all_regions
    elsif !all_regions.include?(datastore['REGION'])
      fail_with(Failure::BadConfig, "Invalid AWS region: #{datastore['REGION']}")
    else
      regions = [datastore['REGION']]
    end

    regions.uniq.each do |region|
      vprint_status "Checking #{region}..."
      ec2 = Aws::EC2::Resource.new(
        region: region,
        access_key_id: datastore['ACCESS_KEY_ID'],
        secret_access_key: datastore['SECRET_ACCESS_KEY']
      )

      instances = datastore['LIMIT'] ? ec2.instances.limit(datastore['LIMIT']) : ec2.instances
      print_status "Found #{ec2.instances.count} instances in #{region}"

      instances.each do |i|
        describe_ec2_instance(i)
      end
    end
  rescue Seahorse::Client::NetworkingError => e
    print_error e.message
    print_error 'Confirm region name (eg. us-west-2) is valid or blank before retrying'
  rescue Aws::EC2::Errors::ServiceError => e
    fail_with(Failure::UnexpectedReply, e.message)
  end
end
