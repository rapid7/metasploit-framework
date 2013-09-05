##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'           => 'Windows Gather Forensics Duqu Registry Check',
      'Description'    => %q{ This module searches for CVE-2011-3402 (Duqu) related registry artifacts.},
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Marcus J. Carey <mjc[at]threatagent.com>'],
      'Platform'       => [ 'win' ],
      'SessionTypes'   => [ 'meterpreter' ],
      'References'     =>
        [
          [ 'CVE', '2011-3402'  ],
          [ 'URL', 'http://r-7.co/w5h7fY' ]
        ]
    ))
  end

  def run
    # Registry artifacts sourced from Symantec report
    artifacts =
      [
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\"CFID"',
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\CFID',
        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\JmiNET3',
        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\JmiNET3\FILTER'
      ]
    match = 0

    print_status("Searching registry on #{sysinfo['Computer']} for CVE-2011-3402 exploitation [Duqu] artifacts.")

    begin
      artifacts.each do |artifact|
        (path, query) = parse_path(artifact)
        has_key = registry_enumkeys(path)
        has_val = registry_enumvals(path)

        if has_key.include?(query) or has_val.include?(query)
          print_good("#{sysinfo['Computer']}: #{path}\\#{query} found in registry.")
          match += 1
          report_vuln(
            :host          => session.session_host,
            :name          => self.name,
            :info          => "Module #{self.fullname} detected #{path}\\#{query} - possible CVE-2011-3402 exploitation [Duqu] artifact.",
            :refs          => self.references,
            :exploited_at  => Time.now.utc
          )
        end
      end
    rescue # Probably should do something here...
    end

    print_status("#{sysinfo['Computer']}: #{match.to_s} artifact(s) found in registry.")

  end

  def parse_path(artifact)
    parts = artifact.split("\\")
    query = parts[-1]
    parts.pop
    path = parts.join("\\")
    return path, query
  end
end
