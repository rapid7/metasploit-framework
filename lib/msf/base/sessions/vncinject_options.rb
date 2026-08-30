# -*- coding: binary -*-

module Msf
module Sessions
module VncInjectOptions

  def initialize(info = {})
    super(info)

    # Override the DLL path with the path to the meterpreter server DLL
    register_options(
      [
        OptPort.new('VNCPORT',
          [
            true,
            "The local port to use for the VNC proxy",
            5900
          ]),
        OptAddress.new('VNCHOST',
          [
            true,
            "The local host to use for the VNC proxy",
            '127.0.0.1'
          ]),
        OptBool.new('DisableCourtesyShell',
          [
            false,
            "Disables the Metasploit Courtesy shell",
            true
          ]),
        OptBool.new('ViewOnly',
          [
            false,
            "Runs the viewer in view mode",
            true
          ]),
        OptBool.new('AUTOVNC',
          [
            true,
            "Automatically launch VNC viewer if present",
            true
          ])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('DisableSessionTracking',
          [
            false,
            "Disables the VNC payload from following the active session as users log in an out of the input desktop",
            false
          ])
      ], self.class)
    deregister_options('DLL')

  end

  #
  # The library name that we're injecting the DLL as can be random.
  #
  def library_name
    Rex::Text::rand_text_alpha(8) + ".dll"
  end

  #
  # If the AUTOVNC flag is set to true, automatically try to launch VNC
  # viewer.
  #
  def on_session(session)
    # Taken from: https://github.com/rapid7/metasploit-framework/blob/73a0914c4ac1d4c01919fb3b7dc1260c72ad6122/lib/msf/base/sessions/command_shell_options.rb#L35
    platform = nil
    if self.platform and self.platform.kind_of? Msf::Module::PlatformList
      platform = self.platform.platforms.first.realname.downcase
    end
    if self.platform and self.platform.kind_of? Msf::Module::Platform
      platform = self.platform.realname.downcase
    end

    # a blank platform is *all* platforms and used by the generic modules, in that case only set this instance if it was
    # not previously set to a more specific value through some means
    session.platform = platform unless platform.blank? && !session.platform.blank?

    if self.arch
      if self.arch.kind_of?(Array)
        session.arch = self.arch.join('')
      else
        session.arch = self.arch
      end
    end

    # Calculate the flags to send to the DLL
    flags = 0

    flags |= 1 if (datastore['DisableCourtesyShell'])
    flags |= 2 if (datastore['DisableSessionTracking'])

    # Transmit the one byte flag
    session.rstream.put([ flags ].pack('C'))

    # Set up the local relay
    print_status("Starting local TCP relay on #{datastore['VNCHOST']}:#{datastore['VNCPORT']}...")

    session.setup_relay(datastore['VNCPORT'], datastore['VNCHOST'])

    print_status("Local TCP relay started.")

    # If the AUTOVNC flag is set, launch VNC viewer.
    if datastore['AUTOVNC']
      if (session.autovnc(datastore['ViewOnly']))
        print_status("Launched vncviewer.")
      else
        print_error("Failed to launch vncviewer.  Is it installed and in your path?")
      end
    end

    super
  end

end
end
end

