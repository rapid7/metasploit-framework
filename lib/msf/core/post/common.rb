# -*- coding: binary -*-

module Msf::Post::Common

  def rhost
    return nil unless session

    case session.type
    when 'meterpreter'
      session.sock.peerhost
    when 'shell'
      session.session_host
    end
  end

  def rport
    case session.type
    when 'meterpreter'
      session.sock.peerport
    when 'shell'
      session.session_port
    end
  end

  def peer
    "#{rhost}:#{rport}"
  end

  #
  # Checks if the remote system has a process with ID +pid+
  #
  def has_pid?(pid)
    pid_list = []
    case client.type
    when /meterpreter/
      pid_list = client.sys.process.processes.collect {|e| e['pid']}
    when /shell/
      if client.platform =~ /win/
        o = cmd_exec('tasklist /FO LIST')
        pid_list = o.scan(/^PID:\s+(\d+)/).flatten
      else
        o = cmd_exec('ps ax')
        pid_list = o.scan(/^\s*(\d+)/).flatten
      end

      pid_list = pid_list.collect {|e| e.to_i}
    end

    pid_list.include?(pid)
  end


  # Returns the target architecture.
  # You should use this instead of session.platform, because of the following reasons:
  # 1. session.platform doesn't always give you an arch. For example: a shell session.
  # 2. session.platform doesn't mean the target platform/arch, it means whatever the session is.
  #    For example: you can use a python meterpreter on a Windows platform, and you will
  #    get 'python/python' as your arch/platform, and not 'x86/win32'.
  #
  # @return [String] The archtecture recognizable by framework's ARCH_TYPES.
  def get_target_arch
    arch = nil

    case session.type
    when 'meterpreter'
      arch = get_recognizable_arch(client.sys.config.sysinfo['Architecture'])
    when 'shell'
      if session.platform =~ /win/
        arch = get_recognizable_arch(get_env('PROCESSOR_ARCHITECTURE').strip)
      else
        arch = get_recognizable_arch(get_env('MACHTYPE').strip)
      end
    end

    arch
  end


  # Returns the target OS.
  # You should use this instead of session.platform, because of the following reasons:
  # 1. session.platform doesn't always provide a consistent OS name. For example: for a Windows
  #    target, session.platform might return 'win32', which isn't recognized by Msf::Module::Platform.
  # 2. session.platform doesn't mean the target platform/arch, it means whatever the session is.
  #    For example: You can use a python meterpreter on a Windows platform, and you will get
  #    'python/python', as your arch/platform, and not 'windows'.
  #
  # @return [String] The OS name recognizable by Msf::Module::Platform.
  def get_target_os
    os = nil
    info = ''

    case session.type
    when 'meterpreter'
      info = client.sys.config.sysinfo['OS']
    when 'shell'
      if session.platform =~ /win/
        info = get_env('OS').strip
      else
        info = cmd_exec('uname -s').strip
      end
    end

    case info
    when /windows/i
      os = Msf::Module::Platform::Windows.realname.downcase
    when /darwin/i
      os = Msf::Module::Platform::OSX.realname.downcase
    when /freebsd/i
      os = Msf::Module::Platform::FreeBSD.realname.downcase
    when /GENERIC\.MP/i, /netbsd/i
      os =  Msf::Module::Platform::BSD.realname.downcase
    else
      os = Msf::Module::Platform::Linux.realname.downcase
    end


    os
  end

  #
  # Executes +cmd+ on the remote system
  #
  # On Windows meterpreter, this will go through CreateProcess as the
  # "commandLine" parameter. This means it will follow the same rules as
  # Windows' path disambiguation. For example, if you were to call this method
  # thusly:
  #
  #     cmd_exec("c:\\program files\\sub dir\\program name")
  #
  # Windows would look for these executables, in this order, passing the rest
  # of the line as arguments:
  #
  #     c:\program.exe
  #     c:\program files\sub.exe
  #     c:\program files\sub dir\program.exe
  #     c:\program files\sub dir\program name.exe
  #
  # On POSIX meterpreter, if +args+ is set or if +cmd+ contains shell
  # metacharacters, the server will run the whole thing in /bin/sh. Otherwise,
  # (cmd is a single path and there are no arguments), it will execve the given
  # executable.
  #
  # On Java, it is passed through Runtime.getRuntime().exec(String) and PHP
  # uses proc_open() both of which have similar semantics to POSIX.
  #
  # On shell sessions, this passes +cmd+ directly the session's
  # +shell_command_token+ method.
  #
  # Returns a (possibly multi-line) String.
  #
  def cmd_exec(cmd, args=nil, time_out=15)
    case session.type
    when /meterpreter/
      #
      # The meterpreter API requires arguments to come separately from the
      # executable path. This has no effect on Windows where the two are just
      # blithely concatenated and passed to CreateProcess or its brethren. On
      # POSIX, this allows the server to execve just the executable when a
      # shell is not needed. Determining when a shell is not needed is not
      # always easy, so it assumes anything with arguments needs to go through
      # /bin/sh.
      #
      # This problem was originally solved by using Shellwords.shellwords but
      # unfortunately, it is retarded. When a backslash occurs inside double
      # quotes (as is often the case with Windows commands) it inexplicably
      # removes them. So. Shellwords is out.
      #
      # By setting +args+ to an empty string, we can get POSIX to send it
      # through /bin/sh, solving all the pesky parsing troubles, without
      # affecting Windows.
      #
      start = Time.now.to_i
      if args.nil? and cmd =~ /[^a-zA-Z0-9\/._-]/
        args = ""
      end

      session.response_timeout = time_out
      process = session.sys.process.execute(cmd, args, {'Hidden' => true, 'Channelized' => true})
      o = ""
      # Wait up to time_out seconds for the first bytes to arrive
      while (d = process.channel.read)
        if d == ""
          if (Time.now.to_i - start < time_out) && (o == '')
            sleep 0.1
          else
            break
          end
        else
          o << d
        end
      end
      o.chomp! if o

      begin
        process.channel.close
      rescue IOError => e
        # Channel was already closed, but we got the cmd output, so let's soldier on.
      end

      process.close
    when /powershell/
      if args.nil? || args.empty?
        o = session.shell_command("#{cmd}", time_out)
      else
        o = session.shell_command("#{cmd} #{args}", time_out)
      end
      o.chomp! if o
    when /shell/
      if args.nil? || args.empty?
        o = session.shell_command_token("#{cmd}", time_out)
      else
        o = session.shell_command_token("#{cmd} #{args}", time_out)
      end
      o.chomp! if o
    end
    return "" if o.nil?
    return o
  end

  def cmd_exec_get_pid(cmd, args=nil, time_out=15)
    case session.type
      when /meterpreter/
        if args.nil? and cmd =~ /[^a-zA-Z0-9\/._-]/
          args = ""
        end
        session.response_timeout = time_out
        process = session.sys.process.execute(cmd, args, {'Hidden' => true, 'Channelized' => true})
        process.channel.close
        pid = process.pid
        process.close
        pid
      else
        print_error "cmd_exec_get_pid is incompatible with non-meterpreter sessions"
    end
  end

  #
  # Reports to the database that the host is a virtual machine and reports
  # the type of virtual machine it is (e.g VirtualBox, VMware, Xen)
  #
  def report_vm(vm)
    return unless session
    return unless vm
    vm_normal = vm.to_s.strip
    return if vm_normal.empty?
    vm_data = {
      :host => session.target_host,
      :virtual_host => vm_normal
    }
    report_host(vm_data)
  end

  #
  # Returns the value of the environment variable +env+
  #
  def get_env(env)
    case session.type
    when /meterpreter/
      return session.sys.config.getenv(env)
    when /shell/
      if session.platform =~ /win/
        if env[0,1] == '%'
          unless env[-1,1] == '%'
            env << '%'
          end
        else
          env = "%#{env}%"
        end

        return cmd_exec("echo #{env}")
      else
        unless env[0,1] == '$'
          env = "$#{env}"
        end

        return cmd_exec("echo \"#{env}\"")
      end
    end

    nil
  end

  #
  # Returns a hash of environment variables +envs+
  #
  def get_envs(*envs)
    case session.type
    when /meterpreter/
      return session.sys.config.getenvs(*envs)
    when /shell/
      result = {}
      envs.each do |env|
        res = get_env(env)
        result[env] = res unless res.blank?
      end

      return result
    end

    nil
  end

  private

  # Returns an architecture recognizable by ARCH_TYPES.
  #
  # @param [String] target_arch The arch. Example: x86
  # @return [String] One of the archs from ARCH_TYPES.
  def get_recognizable_arch(target_arch)
    arch = nil

    # Special handle some cases that ARCH_TYPES won't recognize.
    # https://msdn.microsoft.com/en-us/library/aa384274.aspx
    case target_arch
    when /i[3456]86|wow64/i
      return ARCH_X86
    when /(amd|ia|x)64/i
      return ARCH_X86_64
    end

    # Detect tricky variants of architecture types upfront

    # Rely on ARCH_TYPES to tell us a framework-recognizable ARCH.
    # Notice we're sorting ARCH_TYPES first, so that the longest string
    # goes first. This step is used because sometimes let's say if the target
    # is 'x86_64', and if the ARCH_X86 kicks in first, then we will get 'x86'
    # instead of x86_64, which is inaccurate.
    recognizable_archs = ARCH_TYPES
    recognizable_archs = recognizable_archs.sort_by {|a| a.length}.reverse
    recognizable_archs.each do |a|
      if target_arch =~ /#{a}/
        arch = a
        break
      end
    end

    arch
  end

end
