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
        'Name'        => 'Amazon Web Services EC2 instance enumeration',
        'Description' => %q(
                          Provided AWS credentials, this module will call the authenticated
                          API of Amazon Web Services to list all EC2 instances associated
                          with the account
                         ),
        'Author'      => [
          'Aaron Soto <aaron.soto@rapid7.com>',
          'RageLtMan <rageltman[at]sempervictus>'
        ],
        'License'     => MSF_LICENSE
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

  def handle_aws_errors(e)
    if e.class.module_parents.include?(Aws)
      fail_with(Failure::UnexpectedReply, e.message)
    else
      raise e
    end
  end

  def enumerate_regions
    return [datastore['REGION']] if datastore['REGION']
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

  def describe_ec2_instance(i)
    print_good "  #{i.id} (#{i.state.name})"
    print_good "    Creation Date:  #{i.launch_time}"
    print_good "    Public IP:      #{i.public_ip_address} (#{i.public_dns_name})"
    print_good "    Private IP:     #{i.public_ip_address} (#{i.private_dns_name})"
    # Report hosts and info
    mac_addr = i.network_interfaces.select { |iface|
      iface.private_ip_address == i.private_ip_address
    }.first.mac_address
    iname = i.tags.find {|t| t.key == 'Name'} ? i.tags.find {|t| t.key == 'Name'}.value : i.private_dns_name
    iinfo = i.tags.find {|t| t.key == 'Description'} ? i.tags.find {|t| t.key == 'Description'}.value : nil
    report_host(
      host: i.private_ip_address,
      mac: mac_addr,
      os_name: i.platform_details,
      os_flavor: i.architecture,
      name: iname,
      info: iinfo,
      comments: "ec2-id: #{i.id}"
    )
    report_note(
      host: i.private_ip_address,
      type: 'ec2.public_ip',
      data: i.public_ip_address
    ) if i.public_ip_address
    report_note(
      host: i.private_ip_address,
      type: 'ec2.public_dns',
      data: i.public_dns_name
    ) if i.public_ip_address and not i.public_dns_name.empty?
    report_note(
      host: i.private_ip_address,
      type: 'ec2.hypervisor',
      data: i.hypervisor
    ) if i.hypervisor

    i.security_groups.each do |s|
      print_good "    Security Group: #{s.group_id}"
      report_note(
        host: i.private_ip_address,
        type: "ec2.#{s.group_id}",
        data: s.group_name
      )
    end

    i.tags.each do |t|
      print_good "    Tag: #{t.key} = #{t.value}"
      report_note(
        host: i.private_ip_address,
        type: "ec2.tag #{t.key}",
        data: t.value
      )
    end
  end

  def run
    regions = enumerate_regions

    regions.uniq.each do |region|
      vprint_status "Checking #{region}..."
      ec2 = Aws::EC2::Resource.new(
        region: region,
        access_key_id: datastore['ACCESS_KEY_ID'],
        secret_access_key: datastore['SECRET_ACCESS_KEY']
      )

      instances = ec2.instances.limit(datastore['LIMIT'])
      print_status "Found #{ec2.instances.count} instances in #{region}"

      instances.each do |i|
        describe_ec2_instance(i)
      end
    end
  rescue Seahorse::Client::NetworkingError => e
    print_error e.message
    print_error 'Confirm region name (eg. us-west-2) is valid or blank before retrying'
  rescue ::Exception => e
    handle_aws_errors(e)
  end
end
