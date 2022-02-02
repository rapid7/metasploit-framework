##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::NagiosXi
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Nagios XI Scanner',
      'Description' => %q{
        The module detects the version of Nagios XI applications and
        suggests matching exploit modules based on the version number.
        Since Nagios XI applications only reveal the version to authenticated
        users, valid credentials for a Nagios XI account are required.
        Alternatively, it is possible to provide a specific Nagios XI version
        number via the `VERSION` option. In that case, the module simply
        suggests matching exploit modules and does not probe the target(s).

      },
      'Author' => [ 'Erik Wynter' ], # @wyntererik
      'License' => MSF_LICENSE,
      'References' => [
        ['CVE', '2019-15949'],
        ['CVE', '2020-5791'],
        ['CVE', '2020-5792'],
        ['CVE', '2020-35578']
      ]
    )
    register_options [
      OptString.new('VERSION', [false, 'Nagios XI version to check against existing exploit modules', nil])
    ]
  end

  def finish_install
    datastore['FINISH_INSTALL']
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def version
    datastore['VERSION']
  end

  def parse_version(nagios_version)
    # Strip the xi- prefix used for Nagios XI versions in the official documentation
    clean_version = nagios_version.downcase.delete_prefix('xi-')

    # Check for special case of 5r1.0, which is actually 5.1.0 but for some reason they still added
    # the `r` used in legacy versions (this is the only version with this format)
    if clean_version == '5r1.0'
      clean_version = '5.1.0'
    end

    # Since we are dealing with a user provided version here, a strict regex check seems appropriate
    # So far all modern Nagios XI versions start with 5. This regex can be updated if Nagios XI 6 ever
    # comes out and modules for this new version are added
    modern_check = clean_version.scan(/5\.\d{1,2}\.\d{1,2}/).flatten.first

    unless modern_check.blank?
      return ['modern', clean_version]
    end

    # Nagios XI legacy version numbers vary a lot, but they always start with a year followed by `r` and a single digit
    legacy_check = clean_version.scan(/(20\d{2}r\d{1})/).flatten.first

    unless legacy_check.blank?
      return ['legacy', clean_version]
    end

    return 'unsupported'
  end

  def rce_check(version, real_target: false)
    version_type, clean_version = parse_version(version)
    if version_type == 'unsupported'
      print_error("Invalid version format: `#{version}`. Please provide an existing Nagios XI version or use `unset VERSION` to cancel")
      return
    end

    if version_type == 'legacy'
      print_error("This module does not support the legacy Nagios XI version #{version}")
      return
    end

    begin
      gem_version = Rex::Version.new(clean_version)
    rescue ArgumentError
      print_error("Invalid version format: `#{version}`. Please provide an existing Nagios XI version or use `unset VERSION` to cancel")
      return
    end

    cve_rce_hash = nagios_xi_rce_check(gem_version)

    if cve_rce_hash.empty?
      print_error("Nagios XI version #{version} doesn't match any exploit modules.")
      return
    end

    # Adjust the output based on whether a version was provided, or we obtained a version from a target
    if real_target
      print_good("The target appears to be vulnerable to the following #{cve_rce_hash.length} exploit(s):")
    else
      print_good("Version #{version} matches the following #{cve_rce_hash.length} exploit(s):")
    end

    print_status('')
    # Get the length of the longest key, this is used to align the output when printing
    max_key_length = 0
    cve_rce_hash.each_key { |k| max_key_length = k.length if k.length > max_key_length }
    # Iterate over the hash, and print out the keys and values while using max_key_length to calculate the padding
    cve_rce_hash.each do |cve, exploit_module|
      padding = (max_key_length + 4) - cve.length
      print_status("\t#{cve}#{' ' * padding}exploit/linux/http/#{exploit_module}")
    end
    print_status('')
    return
  end

  # The first undercore in _target_host is used since this parameter is passed in by default but our code never uses it
  def run_host(_target_host)
    # Check if we have a valid version to test
    if version
      if version.empty?
        print_error('VERSION cannot be empty. Please provide an existing Nagios XI VERSION or use `unset VERSION` to cancel')
        return
      end

      return rce_check(version)
    end

    # Check if we have credentials, if not, try to obtain the Nagios XI version from login.php
    if username.blank? || password.blank?
      print_warning('No credentials provided. Attempting to obtain the Nagios XI version from the login page. This will not work for newer versions.')
      nagios_version_result, error_message = nagios_xi_version_no_auth

      if error_message
        print_error("#{rhost}:#{rport} - #{error_message}")
        print_warning('Please provide a valid Nagios XI USERNAME and PASSWORD, or a specific VERSION to check')
        return
      end

      print_status("Target is Nagios XI with version #{nagios_version_result}")

      # Check if the Nagios XI version matches any exploit modules
      return rce_check(nagios_version_result, real_target: true)
    end

    # Use nagios_xi_login to try and authenticate. If authentication succeeds, nagios_xi_login returns
    # an array containing the http response body of a get request to index.php and the session cookies
    login_result, res_array = nagios_xi_login(username, password, finish_install)
    case login_result
    when 1..3 # An error occurred
      print_error("#{rhost}:#{rport} - #{res_array[0]}")
      return
    when 4 # Nagios XI is not fully installed
      install_result = install_nagios_xi(password)
      if install_result
        print_error("#{rhost}:#{rport} - #{install_result[1]}")
        return
      end

      login_result, res_array = login_after_install_or_license(username, password, finish_install)
      case login_result
      when 1..3 # An error occurred
        print_error("#{rhost}:#{rport} - #{res_array[0]}")
        return
      when 4 # Nagios XI is still not fully installed
        print_error("#{rhost}:#{rport} - Failed to install Nagios XI on the target.")
        return
      end
    end

    # when 5 is excluded from the case statement above to prevent having to use this code block twice.
    # Including when 5 would require using this code block once at the end of the `when 4` code block above, and once here.
    if login_result == 5 # the Nagios XI license agreement has not been signed
      auth_cookies, nsp = res_array
      sign_license_result = sign_license_agreement(auth_cookies, nsp)
      if sign_license_result
        print_error("#{rhost}:#{rport} - #{sign_license_result[1]}")
        return
      end

      login_result, res_array = login_after_install_or_license(username, password, finish_install)
      case login_result
      when 1..3
        print_error("#{rhost}:#{rport} - #{res_array[0]}")
        return
      when 5 # the Nagios XI license agreement still has not been signed
        print_error("#{rhost}:#{rport} - Failed to sign the license agreement.")
        return
      end
    end

    print_good('Successfully authenticated to Nagios XI')

    # Obtain the Nagios XI version
    nagios_version = nagios_xi_version(res_array[0])
    if nagios_version.nil?
      print_error("#{rhost}:#{rport} - Unable to obtain the Nagios XI version from the dashboard")
      return
    end

    print_status("Target is Nagios XI with version #{nagios_version}")

    # Check if the Nagios XI version matches any exploit modules
    rce_check(nagios_version, real_target: true)
  end
end
