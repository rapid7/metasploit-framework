##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# Some of this code was taken from the "jboss_vulnscan" module by: Tyler Krpata
##

require 'rex/proto/http'
require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Jenkins-CI Enumeration',
      'Description' => %q{
        This module enumerates a remote Jenkins-CI installation in an unauthenticated manner, including
        host operating system and Jenkins installation details.
      },
      'Author'      => 'Jeff McCutchan',
      'License'     => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('TARGETURI', [ true,  'The path to the Jenkins-CI application', '/jenkins/' ])
      ])
  end

  def run_host(ip)
    res = send_request_cgi(
      {
      'uri'       => target_uri.path,
      'method'    => 'GET',
      'ctype'     => 'text/plain',
    })

    unless res
      vprint_error("No response received")
      return
    end

    unless res.headers.include?('X-Jenkins')
      vprint_error("responded with #{res.code} but does not seem to be Jenkins")
      return
    end

    version = res.headers['X-Jenkins']
    print_good("#{peer} - Jenkins Version #{version}")
    report_service(
      :host  => rhost,
      :port  => rport,
      :name  => (ssl ? 'https' : 'http'),
      :proto => 'tcp'
    )

    report_web_site(
      :host  => rhost,
      :port  => rport,
      :ssl   => ssl,
      :info  => "Jenkins Version - #{version}"
    )

    # script - exploit module for this
    # view/All/newJob - can be exploited manually
    # asynchPeople - Jenkins users
    # systemInfo - system information
    apps = [
      'script',
      'view/All/newJob',
      'asynchPeople/',
      'systemInfo'
    ]
    apps.each do |app|
      check_app(app)
    end
  end

  def check_app(app)
    uri_path = normalize_uri(target_uri.path, app)
    res = send_request_cgi({
      'uri'       => uri_path,
      'method'    => 'GET',
      'ctype'     => 'text/plain',
    })
    unless res
      vprint_error("Timeout")
      return
    end

    case res.code
    when 200
      print_good("#{full_uri} - #{uri_path} does not require authentication (200)")
      report_note({
        :type  => "jenkins_path",
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :data  => "#{full_uri} - #{uri_path} does not require authentication (200)",
        :update => :unique_data
      })
      case app
      when "systemInfo"
        parse_system_info(res.body)
      when "script"
        report_vuln(
          :host        => rhost,
          :port        => rport,
          :proto       => 'tcp',
          :sname       => (ssl ? 'https' : 'http'),
          :name        => "Jenkins Script-Console Java Execution",
          :info        => "Module #{self.fullname} confirmed access to the Jenkins Script Console with no authentication"
        )
      end
    when 403
      print_status("#{uri_path} restricted (403)")
    when 401
      print_status("#{uri_path} requires authentication (401): #{res.headers['WWW-Authenticate']}")
    when 404
      print_status("#{uri_path} not found (404)")
    when 301
      print_status("#{uri_path} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
    when 302
      print_status("#{uri_path} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
    else
      print_status("#{uri_path} Don't know how to handle response code #{res.code}")
    end
  end

  def parse_system_info(body)
    vprint_status("Getting useful information from systemInfo")
    infos = {
      "os.name"            => nil,
      "os.version"         => nil,
      "sun.os.patch.level" => nil,
      "os.arch"            => nil,
      "user.name"          => nil,
      "USERDOMAIN"         => nil,
      "user.home"          => nil,
      "user.language"      => nil,
      "user.country"       => nil,
      "user.timezone"      => nil,
      "COMPUTERNAME"       => nil,
      "SystemDrive"        => nil,
      "TEMP"               => nil,
      "TMP"                => nil,
      "SHELL"              => nil
    }

    # remove unclosed tags for REXML
    body.gsub!('<wbr>', '')
    body.gsub!('<br>', '')
    doc = REXML::Document.new(body)
    tds = doc.get_elements("//td")
    tds.each_index do |idx|
      td = tds[idx].get_text.to_s.strip
      infos[td] = tds[idx+1].get_text.to_s.strip if infos.has_key?(td)
    end

    fprint = {}
    jinfo  = {}

    # print out the goodies
    infos.each do |k, v|
      next if v.nil?
      v = v.strip
      next if v.length == 0

      jinfo[k.gsub(/\s+/, '_')] = v

      case k
      when "os.name"
        vprint_line("   OS: #{v}")
        fprint['os.product'] = v
      when "os.version"
        vprint_line("   OS Version: #{v}")
        fprint['os.version'] = v
      when "sun.os.patch.level"
        vprint_line("   Patch Level: #{v}")
      when "os.arch"
        vprint_line("   Arch: #{v}")
        fprint['os.arch'] = v
      when "user.name"
        vprint_line("   User: #{v}")
      when "USERDOMAIN"
        vprint_line("   Domain: #{v}")
        fprint['host.domain'] = v
      when "COMPUTERNAME"
        vprint_line("   Computer Name: #{v}")
        fprint['host.name'] = v
      when "SystemDrive"
        vprint_line("   System Drive: #{v}")
      when "SHELL"
        vprint_line("   Shell: #{v}")
      when "TEMP"
        vprint_line("   Temp Directory: #{v}")
      when "TMP"
        vprint_line("   Temp Directory: #{v}")
      when "user.home"
        vprint_line("   Home Directory: #{v}")
      when "user.language"
        vprint_line("   Language: #{v}")
        fprint['os.language'] = v
      when "user.country"
        vprint_line("   Country: #{v}")
      when "user.timezone"
        vprint_line("   Timezone: #{v}")
      end
    end

    # Report a fingerprint.match for OS fingerprinting support, tied to this service
    report_note(:host => rhost, :port => rport, :proto => 'tcp', :ntype => 'fingerprint.match', :data => fprint)

    # Report a jenkins information note for future analysis, tied to this service
    report_note(:host => rhost, :port => rport, :proto => 'tcp', :ntype => 'jenkins.info', :data => jinfo)

    vprint_line
  end
end
