# -*- coding: binary -*-

require 'msf/base'

module Msf
module Simple

###
#
# Wraps interaction with a generated buffer from the framework.
# Its primary use is to transform a raw buffer into another
# format.
#
###
module Buffer

  #
  # Serializes a buffer to a provided format.  The formats supported are raw,
  # num, dword, ruby, python, perl, bash, c, js_be, js_le, java and psh
  #
  def self.transform(buf, fmt = "ruby", var_name = 'buf', encryption_opts={})
    default_wrap = 60

    unless encryption_opts.empty?
      buf = encrypt_buffer(buf, encryption_opts)
    end

    case fmt
      when 'raw'
      when 'num'
        buf = Rex::Text.to_num(buf)
      when 'hex'
        buf = Rex::Text.to_hex(buf, '')
      when 'dword', 'dw'
        buf = Rex::Text.to_dword(buf)
      when 'python', 'py'
        buf = Rex::Text.to_python(buf, default_wrap, var_name)
      when 'ruby', 'rb'
        buf = Rex::Text.to_ruby(buf, default_wrap, var_name)
      when 'perl', 'pl'
        buf = Rex::Text.to_perl(buf, default_wrap, var_name)
      when 'bash', 'sh'
        buf = Rex::Text.to_bash(buf, default_wrap, var_name)
      when 'c'
        buf = Rex::Text.to_c(buf, default_wrap, var_name)
      when 'csharp'
        buf = Rex::Text.to_csharp(buf, default_wrap, var_name)
      when 'js_be'
        buf = Rex::Text.to_unescape(buf, ENDIAN_BIG)
      when 'js_le'
        buf = Rex::Text.to_unescape(buf, ENDIAN_LITTLE)
      when 'java'
        buf = Rex::Text.to_java(buf, var_name)
      when 'powershell', 'ps1'
        buf = Rex::Powershell.to_powershell(buf, var_name)
      when 'vbscript'
        buf = Rex::Text.to_vbscript(buf, var_name)
      when 'vbapplication'
        buf = Rex::Text.to_vbapplication(buf, var_name)
      else
        raise ArgumentError, "Unsupported buffer format: #{fmt}", caller
    end

    return buf
  end

  #
  # Creates a comment using the supplied format.  The formats supported are
  # raw, ruby, python, perl, bash, js_be, js_le, c, and java.
  #
  def self.comment(buf, fmt = "ruby")
    case fmt
      when 'raw'
      when 'num', 'dword', 'dw', 'hex'
        buf = Rex::Text.to_js_comment(buf)
      when 'ruby', 'rb', 'python', 'py'
        buf = Rex::Text.to_ruby_comment(buf)
      when 'perl', 'pl'
        buf = Rex::Text.to_perl_comment(buf)
      when 'bash', 'sh'
        buf = Rex::Text.to_bash_comment(buf)
      when 'c'
        buf = Rex::Text.to_c_comment(buf)
      when 'csharp'
        buf = Rex::Text.to_c_comment(buf)
      when 'js_be', 'js_le'
        buf = Rex::Text.to_js_comment(buf)
      when 'java'
        buf = Rex::Text.to_c_comment(buf)
      else
        raise ArgumentError, "Unsupported buffer format: #{fmt}", caller
    end

    return buf
  end

  #
  # Returns the list of supported formats
  #
  def self.transform_formats
    [
      'bash',
      'c',
      'csharp',
      'dw',
      'dword',
      'hex',
      'java',
      'js_be',
      'js_le',
      'num',
      'perl',
      'pl',
      'powershell',
      'ps1',
      'py',
      'python',
      'raw',
      'rb',
      'ruby',
      'sh',
      'vbapplication',
      'vbscript'
    ]
  end

  def self.encryption_formats
    [
      'xor',
      'base64',
      'aes256',
      'rc4'
    ]
  end

  private

  def self.encrypt_buffer(value, encryption_opts)
    buf = ''

    case encryption_opts[:format]
    when 'aes256'
      if encryption_opts[:iv].blank?
        raise ArgumentError, 'Initialization vector is missing'
      elsif encryption_opts[:key].blank?
        raise ArgumentError, 'Encryption key is missing'
      end

      buf = Rex::Crypto.encrypt_aes256(encryption_opts[:iv], encryption_opts[:key], value)
    when 'base64'
      buf = Rex::Text.encode_base64(value)
    when 'xor'
      if encryption_opts[:key].blank?
        raise ArgumentError, 'XOR key is missing'
      end

      buf = Rex::Text.xor(encryption_opts[:key], value)
    when 'rc4'
      if encryption_opts[:key].blank?
        raise ArgumentError, 'Encryption key is missing'
      end

      buf = Rex::Crypto.rc4(encryption_opts[:key], value)
    else
      raise ArgumentError, "Unsupported encryption format: #{encryption_opts[:format]}", caller
    end

    return buf
  end

end

end
end
