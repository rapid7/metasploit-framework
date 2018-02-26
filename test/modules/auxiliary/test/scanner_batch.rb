##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Simple Recon Module Tester',
      'Description' => 'Simple Recon Module Tester',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT,
      ], self.class)

  end

  def run_batch_size
    3
  end

  def run_batch(batch)
    print_status("Working on batch #{batch.join(",")}")
  end

end
