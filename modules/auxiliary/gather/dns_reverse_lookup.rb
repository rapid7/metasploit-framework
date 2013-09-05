##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require "net/dns/resolver"
require 'rex'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'		   => 'DNS Reverse Lookup Enumeration',
      'Description'	=> %q{
          This module performs DNS reverse lookup against a given IP range in order to
        retrieve valid addresses and names.
      },
      'Author'		=> [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'License'		=> BSD_LICENSE
    ))

    register_options(
      [
        OptAddressRange.new('RANGE', [true, 'IP range to perform reverse lookup against.']),
        OptAddress.new('NS', [ false, "Specify the nameserver to use for queries, otherwise use the system DNS." ])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('RETRY', [ false, "Number of tries to resolve a record if no response is received.", 2]),
        OptInt.new('RETRY_INTERVAL', [ false, "Number of seconds to wait before doing a retry.", 2]),
        OptInt.new('THREADS', [ true, "The number of concurrent threads.", 1])
      ], self.class)
  end

  def run
    @res = Net::DNS::Resolver.new()

    if datastore['RETRY']
      @res.retry = datastore['RETRY'].to_i
    end

    if datastore['RETRY_INTERVAL']
      @res.retry_interval = datastore['RETRY_INTERVAL'].to_i
    end

    @threadnum = datastore['THREADS'].to_i
    switchdns() unless datastore['NS'].nil?
    reverselkp(datastore['RANGE'])
  end

  def reverselkp(iprange)
    print_status("Running reverse lookup against IP range #{iprange}")
    ar = Rex::Socket::RangeWalker.new(iprange)
    tl = []
    while (true)
      # Spawn threads for each host
      while (tl.length <= @threadnum)
        ip = ar.next_ip
        break if not ip
        tl << framework.threads.spawn("Module(#{self.refname})-#{ip}", false, ip.dup) do |tip|
          begin
            query = @res.query(tip)
            query.each_ptr do |addresstp|
              print_status("Host Name: #{addresstp}, IP Address: #{tip.to_s}")
              report_host(
                :host => tip.to_s,
                :name => addresstp
              )
            end
          rescue ::Interrupt
            raise $!
          rescue ::Rex::ConnectionError
          rescue ::Exception => e
            print_error("Error: #{tip}: #{e.message}")
          end
        end
      end
      # Exit once we run out of hosts
      if(tl.length == 0)
        break
      end
      tl.first.join
      tl.delete_if { |t| not t.alive? }
    end
  end

  def switchdns()
    print_status("Using DNS server: #{datastore['NS']}")
    @res.nameserver=(datastore['NS'])
    @nsinuse = datastore['NS']
  end
end

