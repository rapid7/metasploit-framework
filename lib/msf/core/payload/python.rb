# -*- coding: binary -*-

module Msf::Payload::Python

  #
  # Encode the given python command in base64 and wrap it with a stub
  # that will decode and execute it on the fly. The code will be condensed to
  # one line and compatible with all Python versions supported by the Python
  # Meterpreter stage.
  #
  # @param cmd [String] The python code to execute.
  # @return [String] Full python stub to execute the command.
  #
  def self.create_exec_stub(cmd)
    # Base64 encoding is required in order to handle Python's formatting
    b64_stub = "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('#{Rex::Text.encode_base64(cmd)}')[0]))"
    b64_stub
  end

  def py_create_exec_stub(cmd)
    exec_stub = Msf::Payload::Python.create_exec_stub(cmd)
    if @arch.to_set == [ARCH_CMD, ARCH_PYTHON].to_set
      # if the arch is cmd and python, then convert the python code to an OS command
      platforms = (@platform.platforms - [Msf::Module::Platform::Python]).to_set
      if platforms.length > 0 && platforms.subset?([Msf::Module::Platform::Linux, Msf::Module::Platform::OSX, Msf::Module::Platform::Unix].to_set)
        # if the platform is one or more of linux, osx, or unix then echo the payload into an exec that will find the correct python bin automatically
        exec_stub = "echo #{Shellwords.escape(exec_stub)} | exec $(which python || which python3 || which python2) -"
      else
        raise NotImplementedError 'unsupported platform'
      end
    end

    exec_stub
  end

end
