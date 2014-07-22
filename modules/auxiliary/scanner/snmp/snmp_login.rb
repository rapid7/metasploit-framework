##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'openssl'
require 'snmp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'SNMP Community Scanner',
      'Description' => 'Scan for SNMP devices using common community names',
      'Author'      => 'hdm',
      'References'     =>
        [
          [ 'CVE', '1999-0508'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(161),
      Opt::CHOST,
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptString.new('PASSWORD', [ false, 'The password to test' ]),
      OptPath.new('PASS_FILE',  [ false, "File containing communities, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "snmp_default_pass.txt")
      ])
    ], self.class)

    deregister_options('USERNAME', 'USER_FILE', 'USERPASS_FILE')
  end


  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Operate on an entire batch of hosts at once
  def run_batch(batch)

    batch.each do |ip|



    end

  end




end
