##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/dns'
require 'resolv'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'DNS Lookup Result Comparison',
        'Description' => %q{
          This module can be used to determine differences
          in the cache entries between two DNS servers. This is
          primarily useful for detecting cache poisoning attacks,
          but can also be used to detect geo-location load balancing.
        },
        'Author' => [ 'hdm' ],
        'License' => MSF_LICENSE,
        'References' => [
        ],
        'DisclosureDate' => '2008-07-21',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptAddress.new('BASEDNS', [ true, 'The DNS cache server to use as a baseline', '4.2.2.3' ]),
        OptAddress.new('TARGDNS', [ true, 'The DNS cache server to test', nil ]),
        OptString.new('NAMES', [ true, 'The list of host names that should be tested (comma separated)', 'www.google.com,www.yahoo.com,www.msn.com']),
        OptBool.new('CHECK_AUTHORITY', [ false, 'Set this to true to verify authority records', false ]),
        OptBool.new('CHECK_ADDITIONAL', [ false, 'Set this to true to verify additional records', false ]),

      ]
    )
  end

  def run
    base_addr = datastore['BASEDNS']
    targ_addr = datastore['TARGDNS']
    check_ar = datastore['CHECK_ADDITIONAL']
    check_aa = datastore['CHECK_AUTHORITY']
    names = datastore['NAMES'].split(',').map(&:strip)
    recurse = true
    results = {}

    print_status("Comparing results between #{base_addr} and #{targ_addr}...")

    base_sock = Rex::Socket.create_udp(
      'PeerHost' => base_addr,
      'PeerPort' => 53
    )

    targ_sock = Rex::Socket.create_udp(
      'PeerHost' => targ_addr,
      'PeerPort' => 53
    )

    names.each do |entry|
      entry.strip!
      next if entry.empty?

      req = Resolv::DNS::Message.new
      req.add_question(entry, Resolv::DNS::Resource::IN::A)
      req.rd = recurse ? 1 : 0

      buf = req.encode
      print_status("Querying servers for #{entry}...")
      base_sock.put(buf)
      targ_sock.put(buf)

      base_res, = base_sock.recvfrom(65535, 3.0)
      targ_res, = targ_sock.recvfrom(65535, 3.0)

      if !(base_res && targ_res && !base_res.empty? && !targ_res.empty?)
        print_error('  Error: The baseline server did not respond to our request.') if !(base_res && !base_res.empty?)
        print_error('  Error: The target server did not respond to our request.') if !(targ_res && !targ_res.empty?)
        next
      end

      base_res = Resolv::DNS::Message.decode(base_res)
      targ_res = Resolv::DNS::Message.decode(targ_res)

      [base_res, targ_res].each do |res|
        hkey = (res == base_res) ? :base : :targ

        rrset = res.answer
        rrset += res.authority if check_aa
        rrset += res.additional if check_ar

        rrset.each do |ref|
          name, _, data = ref

          name.to_s
          anst = data.class.to_s.gsub(/^.*Resolv::DNS::Resource::IN::/, '')
          case data
          when Resolv::DNS::Resource::IN::NS
            data = data.name.to_s
          when Resolv::DNS::Resource::IN::MX
            data = data.exchange.to_s
          when Resolv::DNS::Resource::IN::A
            data = data.address.to_s
          when Resolv::DNS::Resource::IN::TXT
            data = data.strings.join
          when Resolv::DNS::Resource::IN::CNAME
            data = data.name.to_s
          else
            data = anst
          end

          results[entry] ||= {}
          results[entry][hkey] ||= {}
          results[entry][hkey][anst] ||= []
          results[entry][hkey][anst] << data
        end
      end
    end

    [ base_sock, targ_sock ].each(&:close)

    print_status("Analyzing results for #{results.keys.length} entries...")

    results.each_key do |entry|
      n_add = []
      n_sub = []

      # Look for additional entries in the target NS
      if (results[entry][:targ])
        results[entry][:targ].each_key do |rtype|
          next unless !(results[entry][:base]) || !(results[entry][:base][rtype])

          results[entry][:targ][rtype].sort.each do |ref|
            n_sub << ("  + #{entry} #{rtype} #{ref}")
          end
        end
      end

      if (results[entry][:base])
        results[entry][:base].each_key do |rtype|
          # Look for missing entries in the target NS
          if !(results[entry][:targ]) || !(results[entry][:targ][rtype])
            results[entry][:base][rtype].sort.each do |ref|
              n_sub << ("  - #{entry} #{rtype} #{ref}")
            end
            next
          end

          # Look for differences
          next unless (results[entry][:base][rtype].sort != results[entry][:targ][rtype].sort)

          results[entry][:base][rtype].sort.each do |ref|
            if !results[entry][:targ][rtype].include?(ref)
              n_sub << ("  - #{entry} #{rtype} #{ref}")
            end
          end
          results[entry][:targ][rtype].sort.each do |ref|
            if !results[entry][:base][rtype].include?(ref)
              n_add << ("  + #{entry} #{rtype} #{ref}")
            end
          end
        end
      end

      n_sub.each { |s| print_status(s) }
      n_add.each { |s| print_status(s) }
    end
  end
end
