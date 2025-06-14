# -*- coding: binary -*-

module Msf::Sessions
  ###
  #
  # This class provides basic interaction with a ChannelFD
  # abstraction provided by the Rex::Proto::Ssh wrapper
  # around HrrRbSsh.
  #
  #  Date:    June 22, 2019
  #  Author:  RageLtMan
  #
  ###
  class SshCommandShellReverse < Msf::Sessions::CommandShell

    #
    # This interface supports basic interaction.
    #
    include Msf::Session::Basic

    #
    # This interface supports interacting with a single command shell.
    #
    include Msf::Session::Provider::SingleCommandShell

    ##
    #
    # Returns the session description.
    #
    def desc
      'SSH command shell'
    end

    def shell_command(cmd, timeout = 5)
      # Send the command to the session's stdin.
      shell_write(cmd + "\n")

      etime = ::Time.now.to_f + timeout
      buff = ""

      # Keep reading data until no more data is available or the timeout is
      # reached.
      while ::Time.now.to_f < etime && ::IO.select([rstream.fd_rd], nil, nil, timeout)
        res = shell_read(-1, 0.01)
        buff << res if res
        timeout = etime - ::Time.now.to_f
      end

      buff
    end

    protected

    def _interact_stream
      fdr = [rstream.fd_rd, user_input.fd]
      fdw = [rstream.fd_wr, user_input.fd]
      while interacting
        sd = Rex::ThreadSafe.select(fdr, nil, fdw, 0.5)
        next unless sd

        if sd[0].include? rstream.fd_rd
          user_output.print(shell_read)
        end
        if sd[0].include? user_input.fd
          run_single((user_input.gets || '').chomp("\n"))
        end
        Thread.pass
      end
    end

  end
end
