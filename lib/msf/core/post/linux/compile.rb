# -*- coding: binary -*-
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/unix'

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
    return false unless datastore['COMPILE'].eql?('Auto') || datastore['COMPILE'].eql?('True')

    if has_gcc?
      vprint_good 'gcc is installed'
      return true
    end

    unless datastore['COMPILE'].eql? 'Auto'
      fail_with Module::Failure::BadConfig, 'gcc is not installed. Set COMPILE False to upload a pre-compiled executable.'
    end
  end

  def upload_and_compile(path, data, gcc_args='')
    write_file "#{path}.c", strip_comments(data)

    gcc_cmd = "gcc -o #{path} #{path}.c"
    if session.type.eql? 'shell'
      gcc_cmd = "PATH=\"$PATH:/usr/bin/\" #{gcc_cmd}"
    end

    unless gcc_args.to_s.blank?
      gcc_cmd << " #{gcc_args}"
    end

    output = cmd_exec gcc_cmd
    rm_f "#{path}.c"

    unless output.blank?
      print_error output
      fail_with Module::Failure::BadConfig, "#{path}.c failed to compile. Set COMPILE False to upload a pre-compiled executable."
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
