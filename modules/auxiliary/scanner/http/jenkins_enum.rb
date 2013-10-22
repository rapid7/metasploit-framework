##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# Some of this code was taken from the "jboss_vulnscan" module by: Tyler Krpata
##

require 'rex/proto/http'
require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Jenkins Vulnerability Scanner',
      'Description' => %q{
        This module scans a Jenkins installation for a few vulnerabilities.
      },
      'Author'      => 'Jeff McCutchan',
      'License'     => MSF_LICENSE
      ))

    register_options(
      [
        OptString.new('TARGETURI',  [ true,  "Path to Jenkins instance", "/jenkins/"]),
      ], self.class)
  end

  def run_host(ip)
    res = send_request_cgi(
      {
      'uri'       => target_uri.path,
      'method'    => 'GET',
      'ctype'     => 'text/plain',
    })

    unless res
      vprint_error("#{peer} - No response received")
      return
    end

    unless res.headers.include?('X-Jenkins')
      vprint_error("#{peer} - responded with #{res.code} but does not seem to be Jenkins")
      return
    end

    version = res.headers['X-Jenkins']
    vprint_status("#{peer} - Jenkins Version - #{version}")
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
      vprint_error("#{peer} - Timeout")
      return
    end

    case res.code
    when 200
      print_good("#{peer} - #{uri_path} does not require authentication (200)")
      report_note({
        :type  => "jenkins_path",
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :data  => "#{uri_path} does not require authentication (200)",
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
      vprint_status("#{peer} - #{uri_path} restricted (403)")
    when 401
      vprint_status("#{peer} - #{uri_path} requires authentication (401): #{res.headers['WWW-Authenticate']}")
    when 404
      vprint_status("#{peer} - #{uri_path} not found (404)")
    when 301
      vprint_status("#{peer} - #{uri_path} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
    when 302
      vprint_status("#{peer} - #{uri_path} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
    else
      vprint_status("#{peer} - #{uri_path} Don't know how to handle response code #{res.code}")
    end
  end

  def parse_system_info(body)
    vprint_status("#{peer} - Getting useful information from systemInfo")
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

    # print out the goodies
    infos.each do |k, v|
      next if v.nil?
      case k
      when "os.name"
        vprint_line("   OS: #{v}")
        report_host({:host => rhost, :os_name => v})
      when "os.version"
        vprint_line("   OS Version: #{v}")
        report_host({:host => rhost, :os_flavor => v})
      when "sun.os.patch.level"
        vprint_line("   Patch Level: #{v}")
      when "os.arch"
        vprint_line("   Arch: #{v}")
        report_note({
          :type  => "system_arch",
          :host  => rhost,
          :data  => "Arch: #{v}",
          :update => :unique_data
        })
      when "user.name"
        vprint_line("   User: #{v}")
        report_note({
          :type  => "jenkins_user",
          :host  => rhost,
          :port  => rport,
          :proto => 'tcp',
          :data  => "User: #{v}",
          :update => :unique_data
        })
      when "USERDOMAIN"
        vprint_line("   Domain: #{v}")
        report_note({
          :type  => "system_domain",
          :host  => rhost,
          :data  => "Domain: #{v}",
          :update => :unique_data
        })
      when "COMPUTERNAME"
        vprint_line("   Computer Name: #{v}")
        report_note({
          :type  => "system_computer",
          :host  => rhost,
          :data  => "Computer Name: #{v}",
          :update => :unique_data
        })
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
        report_note({
          :type  => "system_lang",
          :host  => rhost,
          :data  => "Language: #{v}",
          :update => :unique_data
        })
      when "user.country"
        vprint_line("   Country: #{v}")
        report_note({
          :type  => "system_country",
          :host  => rhost,
          :data  => "Country: #{v}",
          :update => :unique_data
        })
      when "user.timezone"
        vprint_line("   Timezone: #{v}")
        report_note({
          :type  => "system_timezone",
          :host  => rhost,
          :data  => "Timezone: #{v}",
          :update => :unique_data
        })
      end
    end
    vprint_line('')
  end
end
