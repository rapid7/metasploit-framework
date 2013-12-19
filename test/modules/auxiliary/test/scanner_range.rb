##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Simple Recon Module Tester',
      'Version'     => '$Revision$',
      'Description' => 'Simple Recon Module Tester',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT,
      ], self.class)

  end

  def run_range(range)
    print_status("Working on range #{range}")
    rw = Rex::Socket::RangeWalker.new(range)
    print_status("RangeWalker: #{rw.inspect}")
  end


end
