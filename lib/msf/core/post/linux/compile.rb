# -*- coding: binary -*-
module Msf
class Post
module Linux
module Compile
  include ::Msf::Post::Common
  include ::Msf::Post::File
  include ::Msf::Post::Unix

  def initialize(info = {})
    super
    register_options( [
      OptEnum.new('COMPILE', [true, 'Compile on target', 'Auto', ['Auto', 'True', 'False']]),
    ], self.class)
  end

  def live_compile?
    return false unless %w{ Auto True }.include?(datastore['COMPILE'])

    if has_gcc?
      vprint_good 'gcc is installed'
      return true
    end

    unless datastore['COMPILE'] == 'Auto'
      fail_with Module::Failure::BadConfig, 'gcc is not installed. Set COMPILE False to upload a pre-compiled executable.'
    end
  end

  def upload_and_compile(path, data, gcc_args='')
    write_file "#{path}.c", strip_comments(data)

    gcc_cmd = "gcc -o '#{path}' '#{path}.c'"
    if session.type == 'shell'
      gcc_cmd = "PATH=\"$PATH:/usr/bin/\" #{gcc_cmd}"
    end

    unless gcc_args.to_s.blank?
      gcc_cmd << " #{gcc_args}"
    end

    output = cmd_exec gcc_cmd
    rm_f "#{path}.c"

    unless output.blank?
      print_error output
      message = "#{path}.c failed to compile."
      # don't mention the COMPILE option if it was deregistered
      message << ' Set COMPILE to False to upload a pre-compiled executable.' if options.include?('COMPILE')
      fail_with Module::Failure::BadConfig, message
    end

    chmod path
  end

  def strip_comments(c_code)
    c_code.gsub(%r{/\*.*?\*/}m, '').gsub(%r{^\s*//.*$}, '')
  end

end # Compile
end # Linux
end # Post
end # Msf
