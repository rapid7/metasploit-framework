# Provides an animated spinner.
#
# See GitHub issue #4147, as this may be blocking some Windows instances, which is why Windows platforms should simply
# return immediately.
class Metasploit::Framework::Command::Console::Spinner
  include Celluloid

  def announce
    $stderr.print "[*] Starting the Metasploit Framework console..."
  end

  def revolve
    %q{/-\|}.each_char do |c|
      $stderr.print c
      $stderr.print "\b"
    end

    async.revolve
  end

  def spin
    if Rex::Compat.is_windows || Rex::Compat.is_cygwin
      terminate
      return
    end

    announce

    async.revolve
  end
end