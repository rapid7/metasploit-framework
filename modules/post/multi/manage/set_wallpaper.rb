##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Multi Manage Set Wallpaper',
        'Description'   => %q(
          This module will set the desktop wallpaper background on the specified session.
          The method of setting the wallpaper depends on the platform type.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => [ 'timwr'],
        'Platform'      => [ 'win', 'osx', 'linux', 'android' ],
        'SessionTypes'  => [ 'meterpreter' ]
      )
    )

    register_options(
      [
        OptPath.new('WALLPAPER_FILE', [true, 'The local wallpaper file to set on the remote session'])
      ])
  end

  def upload_wallpaper(tempdir, file)
    remote_file = "#{tempdir}#{File.basename(file)}"
    print_status("#{peer} - Uploading to #{remote_file}")

    write_file(remote_file, File.binread(file))
    print_status("#{peer} - Uploaded to #{remote_file}")
    remote_file
  end

  #
  # The OS X version uses an AppleScript to do this
  #
  def osx_set_wallpaper(file)
    remote_file = upload_wallpaper("/tmp/", file)
    script = %(osascript -e 'tell application "Finder" to set desktop picture to POSIX file "#{remote_file}"')
    begin
      cmd_exec(script)
    rescue EOFError
      return false
    end
    true
  end

  #
  # The Windows version uses the SystemParametersInfo call
  #
  def win_set_wallpaper(file)
    remote_file = upload_wallpaper("%TEMP%\\", file)
    client.railgun.user32.SystemParametersInfoA(0x0014, nil, remote_file, 0x2) != 0
  end

  #
  # The Android version uses the set_wallpaper command
  #
  def android_set_wallpaper(file)
    client.android.set_wallpaper(File.binread(file))
    true
  end

  def os_set_wallpaper(file)
    case session.platform
    when 'osx'
      osx_set_wallpaper(file)
    when 'windows'
      win_set_wallpaper(file)
    when 'android'
      android_set_wallpaper(file)
    end
  end

  def run
    file = datastore['WALLPAPER_FILE']
    if os_set_wallpaper(file)
      print_good("#{peer} - The wallpaper has been set")
    else
      print_error("#{peer} - Unable to set the wallpaper")
    end
  end
end
