# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Kubernetes
  include Msf::Exploit::Remote::HTTP::Kubernetes::Enumeration

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kubernetes Enumeration',
        'Description' => %q{
          Enumerate a Kubernetes API to report useful resources such as available namespaces,
          pods, secrets, etc.

          Useful resources will be highlighted using the HIGHLIGHT_NAME_PATTERN option.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'alanfoster',
          'Spencer McIntyre'
        ],
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'Stability' => [CRASH_SAFE]
        },
        'DefaultOptions' => {
          'SSL' => true
        },
        'Actions' => [
          ['all', { 'Description' => 'enumerate all resources' }],
          ['version', { 'Description' => 'enumerate version' }],
          ['auth', { 'Description' => 'enumerate auth' }],
          ['namespace', { 'Description' => 'enumerate namespace' }],
          ['namespaces', { 'Description' => 'enumerate namespaces' }],
          ['pod', { 'Description' => 'enumerate pod' }],
          ['pods', { 'Description' => 'enumerate pods' }],
          ['secret', { 'Description' => 'enumerate secret' }],
          ['secrets', { 'Description' => 'enumerate secrets' }],
        ],
        'DefaultAction' => 'all',
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['meterpreter']
      )
    )

    register_options(
      [
        Opt::RHOSTS(nil, false),
        Opt::RPORT(nil, false),
        Msf::OptInt.new('SESSION', [false, 'An optional session to use for configuration']),
        OptRegexp.new('HIGHLIGHT_NAME_PATTERN', [true, 'PCRE regex of resource names to highlight', 'username|password|user|pass']),
        OptString.new('NAME', [false, 'The name of the resource to enumerate', nil]),
        OptEnum.new('OUTPUT', [true, 'output format to use', 'table', ['table', 'json']])
      ]
    )
  end

  def output_for(type)
    case type
    when 'table'
      Msf::Exploit::Remote::HTTP::Kubernetes::Output::Table.new(self, highlight_name_pattern: datastore['HIGHLIGHT_NAME_PATTERN'])
    when 'json'
      Msf::Exploit::Remote::HTTP::Kubernetes::Output::JSON.new(self)
    end
  end

  def run
    if session
      print_status("Routing traffic through session: #{session.sid}")
      configure_via_session
    end
    validate_configuration!

    @kubernetes_client = Msf::Exploit::Remote::HTTP::Kubernetes::Client.new({ http_client: self, token: api_token })
    @output = output_for(datastore['output'])

    case action.name
    when 'all'
      enum_all
    when 'version'
      enum_version
    when 'auth'
      enum_auth(datastore['NAMESPACE'])
    when 'namespaces', 'namespace'
      enum_namespaces(name: datastore['NAME'])
    when 'pods', 'pod'
      enum_pods(datastore['NAMESPACE'], name: datastore['NAME'])
    when 'secret', 'secrets'
      enum_secrets(datastore['NAMESPACE'], name: datastore['NAME'])
    end
  rescue Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError => e
    print_error(e.message)
  end
end
