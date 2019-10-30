##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize(info = {})
    super(
      update_info(
        info,
        # TODO: fill in all of this
        'Name'           => 'UDP Scanner Example',
        'Description'    => %q(
          This module is an example of how to send probes to UDP services
          en-masse, analyze any responses, and then report on any discovered
          hosts, services, vulnerabilities or otherwise noteworthy things.
          Simply address any of the TODOs.
        ),
        'Author'         => 'Joe Contributor <joe_contributor[at]example.com>',
        'DisclosureDate' => 'Mar 15 2014',
        'License'        => MSF_LICENSE,
        'References'     => [
          [ 'CVE', '0000-0000' ], # remove or update if CVE exists
          [ 'URL', 'https://SomeURLinCyberspace.local' ]
        ]
      )
    )

    register_options(
      [
        # TODO: change to the port you need to scan
        Opt::RPORT(12345)
      ]
    )

    # TODO: add any advanced, special options here, otherwise remove
    register_advanced_options(
      [
        OptBool.new('SPECIAL', [true, 'Try this special thing', false])
      ]
    )
  end

  def setup
    super
    # TODO: do any sort of preliminary sanity checking, like perhaps validating some options
    # in the datastore, etc.
  end

  # TODO: construct the appropriate probe here.
  def build_probe
    @probe ||= 'abracadabra!'
  end

  # TODO: this is called before the scan block for each batch of hosts.  Do any
  # per-batch setup here, otherwise remove it.
  def scanner_prescan(batch)
    super
  end

  # TODO: this is called for each IP in the batch.  This will send all of the
  # necessary probes.  If something different must be done for each IP, do it
  # here, otherwise remove it.
  def scan_host(ip)
    super
  end

  # Called for each response packet
  def scanner_process(response, src_host, _src_port)
    # TODO: inspect each response, perhaps confirming that it is a valid
    # response for the service/protocol in question and/or analyzing it more
    # closely.  In this case, we simply check to see that it is of reasonable
    # size and storing a result for this host iff so.  Note that src_port may
    # not actually be the same as the original RPORT for some services if they
    # respond back from different ports
    return unless response.size >= 42
    @results[src_host] ||= []

    # TODO: store something about this response, perhaps the response itself,
    # some metadata obtained by analyzing it, the proof that it is vulnerable
    # to something, etc.  In this example, we simply look for any response
    # with a sequence of 5 useful ASCII characters and, iff found, we store
    # that sequence
    /(?<relevant>[\x20-\x7E]{5})/ =~ response && @results[src_host] << relevant
  end

  # Called after the scan block
  def scanner_postscan(_batch)
    @results.each_pair do |host, relevant_responses|
      peer = "#{host}:#{rport}"

      # report on the host
      report_host(host: host)

      # report on the service, since it responded
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'example',
        # show at most 4 relevant responses
        info: relevant_responses[0, 4].join(',')
      )

      if relevant_responses.empty?
        vprint_status("#{peer} Not vulnerable to something")
      else
        print_good("#{peer} Vulnerable to something!")
        report_vuln(
          host: host,
          port: rport,
          proto: 'udp',
          name: 'something!',
          info: "Got #{relevant_responses.size} response(s)",
          refs: references
        )
      end
    end
  end
end
