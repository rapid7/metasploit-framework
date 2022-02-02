##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Windows Antivirus Exclusions Enumeration',
        'Description'   => %q(
          This module will enumerate the file, directory, process and
          extension-based exclusions from supported AV products, which
          currently includes Microsoft Defender, Microsoft Security
          Essentials/Antimalware, and Symantec Endpoint Protection.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Andrew Smith', # original metasploit module
          'Jon Hart <jon_hart[at]rapid7.com>' # improved metasploit module
        ],
        'Platform'      => [ 'win' ],
        # XXX: this will work with 'shell' when the sysinfo parts are removed
        # and https://github.com/rapid7/metasploit-framework/issues/6328 and
        # perhaps https://github.com/rapid7/metasploit-framework/issues/6316
        # are fixed
        'SessionTypes'  => [ 'meterpreter' ]
      )
    )

    register_options(
      [
        OptBool.new('DEFENDER', [true, 'Enumerate exclusions for Microsoft Defender', true]),
        OptBool.new('ESSENTIALS', [true, 'Enumerate exclusions for Microsoft Security Essentials/Antimalware', true]),
        OptBool.new('SEP', [true, 'Enumerate exclusions for Symantec Endpoint Protection (SEP)', true])
      ]
    )
  end

  DEFENDER = 'Windows Defender'
  DEFENDER_BASE_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender'
  ESSENTIALS = 'Microsoft Security Essentials / Antimalware'
  ESSENTIALS_BASE_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Microsoft Antimalware'
  SEP = 'Symantec Endpoint Protection (SEP)'
  SEP_BASE_KEY = 'HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection'

  def av_installed?(base_key, product)
    if registry_key_exist?(base_key)
      print_good("Found #{product}")
      true
    else
      false
    end
  end

  def excluded_sep
    base_exclusion_key = "#{SEP_BASE_KEY}\\Exclusions\\ScanningEngines\\Directory"
    admin_exclusion_key = "#{base_exclusion_key}\\Admin"
    client_exclusion_key = "#{base_exclusion_key}\\Client"

    admin_paths = []
    if (admin_exclusion_keys = registry_enumkeys(admin_exclusion_key, @registry_view))
      admin_exclusion_keys.map do |key|
        admin_paths << registry_getvaldata("#{admin_exclusion_key}\\#{key}", 'DirectoryName', @registry_view)
      end
      print_exclusions_table(SEP, 'admin path', admin_paths)
    end
    client_paths = []
    if (client_exclusion_keys = registry_enumkeys(client_exclusion_key, @registry_view))
      client_exclusion_keys.map do |key|
        client_paths << registry_getvaldata("#{client_exclusion_key}\\#{key}", 'DirectoryName', @registry_view)
      end
    end
    print_exclusions_table(SEP, 'client path', client_paths)
  end

  def excluded_defender
    print_exclusions_table(DEFENDER, 'extension', registry_enumvals("#{DEFENDER_BASE_KEY}\\Exclusions\\Extensions", @registry_view))
    print_exclusions_table(DEFENDER, 'path', registry_enumvals("#{DEFENDER_BASE_KEY}\\Exclusions\\Paths", @registry_view))
    print_exclusions_table(DEFENDER, 'process', registry_enumvals("#{DEFENDER_BASE_KEY}\\Exclusions\\Processes", @registry_view))
  end

  def excluded_mssec
    print_exclusions_table(ESSENTIALS, 'extension', registry_enumvals("#{ESSENTIALS_BASE_KEY}\\Exclusions\\Extensions", @registry_view))
    print_exclusions_table(ESSENTIALS, 'path', registry_enumvals("#{ESSENTIALS_BASE_KEY}\\Exclusions\\Paths", @registry_view))
    print_exclusions_table(ESSENTIALS, 'process', registry_enumvals("#{ESSENTIALS_BASE_KEY}\\Exclusions\\Processes", @registry_view))
  end

  def print_exclusions_table(product, exclusion_type, exclusions)
    exclusions ||= []
    exclusions = exclusions.compact.reject(&:blank?)
    if exclusions.empty?
      print_status("No #{exclusion_type} exclusions for #{product}")
      return
    end
    table = Rex::Text::Table.new(
      'Header'    => "#{product} excluded #{exclusion_type.pluralize}",
      'Indent'    => 1,
      'Columns'   => [ exclusion_type.capitalize ]
    )
    exclusions.map { |exclusion| table << [exclusion] }
    print_line(table.to_s)
  end

  def setup
    unless datastore['DEFENDER'] || datastore['ESSENTIALS'] || datastore['SEP']
      fail_with(Failure::BadConfig, 'Must set one or more of DEFENDER, ESSENTIALS or SEP to true')
    end

    # all of these target applications seemingly store their registry
    # keys/values at the same architecture of the host, so if we happen to be
    # in a 32-bit process on a 64-bit machine, ensure that we read from the
    # 64-bit keys/values, and otherwise use the native keys/values
    if sysinfo['Architecture'] == ARCH_X64 && session.arch == ARCH_X86
      @registry_view = REGISTRY_VIEW_64_BIT
    else
      @registry_view = REGISTRY_VIEW_NATIVE
    end
  end

  def run
    print_status("Enumerating Excluded Paths for AV on #{sysinfo['Computer']}")

    found = false
    if datastore['DEFENDER'] && av_installed?(DEFENDER_BASE_KEY, DEFENDER)
      found = true
      excluded_defender
    end
    if datastore['ESSENTIALS'] && av_installed?(ESSENTIALS_BASE_KEY, ESSENTIALS)
      found = true
      excluded_mssec
    end
    if datastore['SEP'] && av_installed?(SEP_BASE_KEY, SEP)
      found = true
      excluded_sep
    end

    print_error "No supported AV identified" unless found
  end
end
