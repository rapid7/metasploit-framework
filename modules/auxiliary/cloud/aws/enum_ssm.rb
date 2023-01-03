##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'aws-sdk-ssm'

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Amazon Web Services EC2 instance enumeration',
        'Description' => %q(
                          Provided AWS credentials, this module will call the authenticated
                          API of Amazon Web Services to list all SSM-enabled EC2 instances
                          associated with the account
                         ),
        'Author'      => [
          'Aaron Soto <aaron.soto@rapid7.com>' # EC2 enum module
          'RageLtMan <rageltman[at]sempervictus>' # SSM stuff
        ],
        'Author'      => ['Aaron Soto <aaron.soto@rapid7.com>'],
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
    regions = []

    ec2 = Aws::EC2::Resource.new(
      region: 'us-east-1',
      access_key_id: datastore['ACCESS_KEY_ID'],
      secret_access_key: datastore['SECRET_ACCESS_KEY']
    )

    ec2_regions = ec2.client.describe_regions.data.regions
    ec2_regions.each do |r|
      regions.append(r.region_name)
    end

    regions
  end

  def run
    regions = datastore['REGION'] ? [datastore['REGION']] : regions = enumerate_regions()
    credentials = ::Aws::Credentials.new(datastore['ACCESS_KEY_ID'], datastore['SECRET_ACCESS_KEY'])
    regions.each do |region|
      vprint_status "Checking #{region}..."
      client = ::Aws::SSM::Client.new(
        region: region,
        credentials: credentials,
      )
      inv_params = { filters: [
        {
          key: "AWS:InstanceInformation.InstanceStatus",
          values: ["Terminated"],
          type: "NotEqual",
        },
        {
          key: "AWS:InstanceInformation.ResourceType",
          values: ['EC2Instance'],
          type: "Equal",
        }
      ]}
      ssm_ec2 = client.get_inventory(inv_params).entities.map {|e| e.data["AWS:InstanceInformation"].content}.flatten
      ssm_ec2.each do |ssm_host| 
        vprint_good JSON.pretty_generate(ssm_host)
        # report host?
        # report services?
        # report notes?
        # auto-start SSM session?
      end
  rescue Seahorse::Client::NetworkingError => e
    print_error e.message
    print_error 'Confirm region name (eg. us-west-2) is valid or blank before retrying'
  rescue ::Exception => e
    handle_aws_errors(e)
  end
end
