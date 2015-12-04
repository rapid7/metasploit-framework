##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Windows Antivirus Excluded Locations Enumeration',
        'Description'   => 'This module will enumerate all excluded directories within supported AV products',
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Andrew Smith', # original metasploit module
          'Jon Hart <jon_hart[at]rapid7.com>' # improved metasploit module
        ],
        'Platform'      => [ 'win' ],
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
    admin_exclusion_key = "#{base_exclusion_key}\\Client"

    paths = []
    if (admin_exclusion_keys = registry_enumkeys(admin_exclusion_key))
      admin_exclusion_keys.map do |key|
        paths << registry_getvaldata("#{admin_exclusion_key}\\#{key}", 'DirectoryName') + ' (admin)'
      end
    end
    if (client_exclusion_keys = registry_enumkeys(client_exclusion_key))
      client_exclusion_keys.map do |key|
        paths << registry_getvaldata("#{client_exclusion_key}\\#{key}", 'DirectoryName') + ' (client)'
      end
    end
    print_exclusions_table(SEP, paths)
  end

  def excluded_defender
    print_exclusions_table(DEFENDER, registry_enumvals("#{DEFENDER_BASE_KEY}\\Exclusions\\Paths"))
  end

  def excluded_mssec
    print_exclusions_table(ESSENTIALS, registry_enumvals("#{ESSENTIALS_BASE_KEY}\\Exclusions\\Paths"))
  end

  def print_exclusions_table(product, exclusions)
    unless exclusions && !exclusions.empty?
      print_status("No exclusions for #{product}")
      return
    end
    table = Rex::Ui::Text::Table.new(
      'Header'    => "#{product} excluded paths",
      'Indent'    => 1,
      'Columns'   => %w(path)
    )
    exclusions.map { |exclusion| table << [exclusion] }
    print_line(table.to_s)
  end

  def setup
    if sysinfo['Architecture'] =~ /WOW64/
      fail_with(Failure::BadConfig, 'You are running this module from a 32-bit process on a 64-bit machine. ' \
                'Migrate to a 64-bit process and try again')
    end
    unless datastore['DEFENDER'] || datastore['ESSENTIALS'] || datastore['SEP']
      fail_with(Failure::BadConfig, 'Must set one or more of DEFENDER, ESSENTIALS or SEP to true')
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
