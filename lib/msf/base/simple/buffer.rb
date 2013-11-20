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
  def self.transform(buf, fmt = "ruby")
    case fmt
      when 'raw'
      when 'num'
        buf = Rex::Text.to_num(buf)
      when 'dword', 'dw'
        buf = Rex::Text.to_dword(buf)
      when 'python', 'py'
        buf = Rex::Text.to_python(buf)
      when 'ruby', 'rb'
        buf = Rex::Text.to_ruby(buf)
      when 'perl', 'pl'
        buf = Rex::Text.to_perl(buf)
      when 'bash', 'sh'
        buf = Rex::Text.to_bash(buf)
      when 'c'
        buf = Rex::Text.to_c(buf)
      when 'csharp'
        buf = Rex::Text.to_csharp(buf)
      when 'js_be'
        buf = Rex::Text.to_unescape(buf, ENDIAN_BIG)
      when 'js_le'
        buf = Rex::Text.to_unescape(buf, ENDIAN_LITTLE)
      when 'java'
        buf = Rex::Text.to_java(buf)
      when 'powershell', 'ps1'
        buf = Rex::Text.to_powershell(buf)
      when 'vbscript'
        buf = Rex::Text.to_vbscript(buf)
      when 'vbapplication'
        buf = Rex::Text.to_vbapplication(buf)
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
      when 'num', 'dword', 'dw'
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
    ['raw',
    'num',
    'dword','dw',
    'ruby','rb',
    'perl','pl',
    'bash','sh',
    'c',
    'csharp',
    'js_be',
    'js_le',
    'java',
    'python','py',
    'powershell','ps1',
    'vbscript',
    'vbapplication'
    ]
  end

end

end
end
