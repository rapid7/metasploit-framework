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
      OptEnum.new('COMPILER', [true, 'Compiler to use on target', 'gcc', ['gcc', 'clang']]),
    ], self.class)
  end

  def live_compile?
    return false unless %w{ Auto True }.include?(datastore['COMPILE'])

    if datastore['COMPILER'] == 'gcc' && has_gcc?
      vprint_good 'gcc is installed'
      return true
    elsif datastore['COMPILER'] == 'clang' && has_clang?
      vprint_good 'clang is installed'
      return true
    end

    unless datastore['COMPILE'] == 'Auto'
      fail_with Module::Failure::BadConfig, "#{datastore['COMPILER']} is not installed. Set COMPILE False to upload a pre-compiled executable."
    end

    false
  end

  def upload_and_compile(path, data, compiler_args='')
    write_file "#{path}.c", strip_comments(data)

    compiler_cmd = "#{datastore['COMPILER']} -o '#{path}' '#{path}.c'"
    if session.type == 'shell'
      compiler_cmd = "PATH=\"$PATH:/usr/bin/\" #{compiler_cmd}"
    end

    unless compiler_args.to_s.blank?
      compiler_cmd << " #{compiler_args}"
    end

    verification_token = Rex::Text.rand_text_alphanumeric(8)
    success = cmd_exec("#{compiler_cmd} && echo #{verification_token}")&.include?(verification_token)

    rm_f "#{path}.c"

    unless success
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
