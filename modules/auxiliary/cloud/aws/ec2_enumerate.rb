##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'aws-sdk-ec2'

class MetasploitModule < Msf::Auxiliary
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
        'Author'      => ['Aaron Soto <aaron.soto@rapid7.com>'],
        'License'     => MSF_LICENSE
      )
    )

    register_options(
      [
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

    return regions
  end

  def describe_ec2_instance(i)
    print_good "  #{i.id} (#{i.state.name})"
    print_good "    Creation Date:  #{i.launch_time}"
    print_good "    Public IP:      #{i.public_ip_address} (#{i.public_dns_name})"
    print_good "    Private IP:     #{i.public_ip_address} (#{i.private_dns_name})"
    i.security_groups.each do |s|
      print_good "    Security Group: #{s.group_id}"
    end
  end

  def handle_aws_errors(e)
    if e.class.parents.include?(Aws)
      fail_with(Failure::UnexpectedReply, e.message)
    else
      raise e
    end
  end

  def run
    begin
      if datastore['REGION']
        regions = [datastore['REGION']]
      else
        regions = enumerate_regions()
      end

      regions.each do |region|
        vprint_status "Checking #{region}..."
        ec2 = Aws::EC2::Resource.new(
          region: region,
          access_key_id: datastore['ACCESS_KEY_ID'],
          secret_access_key: datastore['SECRET_ACCESS_KEY']
        )

        if ec2.instances.count > 0
          print_good "Found #{ec2.instances.count} instances in #{region}:"
          ec2.instances.each do |i|
            describe_ec2_instance(i)
          end
        end
      end
    rescue ::Exception => e
      handle_aws_errors(e)
    end
  end
end

