##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Remote Management Interface Discovery',
      'Description' => %q{
        This module can be used to obtain information from the Remote
        Management Interface DCERPC service.
      },
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOST')

    register_options(
      [
        Opt::RPORT(135)
      ], self.class)
  end

  # Obtain information about a single host
  def run_host(ip)
    begin

      ids = dcerpc_mgmt_inq_if_ids(rport)
      return if not ids
      ids.each do |id|
        print_status("UUID #{id[0]} v#{id[1]}")

        reportdata = ""

        stats = dcerpc_mgmt_inq_if_stats(rport)
        if stats
          print_status("\t stats: " + stats.map{|i| "0x%.8x" % i}.join(", "))
          reportdata << "stats: " + stats.map{|i| "0x%.8x" % i}.join(", ") + " "
        end

        live  = dcerpc_mgmt_is_server_listening(rport)
        if live
          print_status("\t listening: %.8x" % live)
          #reportdata << "listening: %.8x" % live + " "
        end

        dead  = dcerpc_mgmt_stop_server_listening(rport)
        if dead
          print_status("\t killed: %.8x" % dead)
          #reportdata << "killed: %.8x" % dead + " "
        end

        princ = dcerpc_mgmt_inq_princ_name(rport)
        if princ
          print_status("\t name: #{princ.unpack("H*")[0]}")
          #reportdata << "name: #{princ.unpack("H*")[0]}"
        end

        ## Add Report
        report_note(
          :host   => ip,
          :proto  => 'tcp',
          :port   => datastore['RPORT'],
          :type   => "DCERPC UUID #{id[0]} v#{id[1]}",
          :data   => reportdata
        )

      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Error: #{e}")
    end
  end

end
