##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'socket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'      => 'Enumerate_subdomains',
      'Description' => %q{
        Enumerate subdomains of domain using a specific list.
      },
      'Author'    => [
        'Kevin Gonzalvo'
      ],
      'License'   => MSF_LICENSE,
      ))
    register_options(
      [
        OptString.new('DOMAIN', [true, 'The target domain']),
        OptPath.new('WORDLIST', [true, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])

      ], self.class)

  end

  def run
    domain = datastore['DOMAIN']
    subdomains = datastore['WORDLIST']
    print_status("Checking subdomains...")
    File.foreach(subdomains) do |subdomain|
      begin
        info = TCPSocket.gethostbyname("#{subdomain.chomp}.#{domain}")
        print_good("#{subdomain.chomp}" + ', ' + info[0] + ', ' + info[3])
      rescue
      end
    end
  end
end
