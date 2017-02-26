# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'
require 'msf/windows_error'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Python_Python < Msf::Sessions::Meterpreter
  ERROR_TYPE_UNKNOWN = 1
  ERROR_TYPE_PYTHON = 2
  ERROR_TYPE_WINDOWS = 3
  # 16-bit CRC-CCITT XMODEM
  PYTHON_ERROR_CRCS = {
    0x02dd => 'NotImplementedError',
    0x049a => 'RuntimeWarning',
    0x09ae => 'IndentationError',
    0x0bf4 => 'SystemExit',
    0x1494 => 'GeneratorExit',
    0x1511 => 'ConnectionRefusedError',
    0x1765 => 'SyntaxWarning',
    0x1f0e => 'SystemError',
    0x33b1 => 'StandardError',
    0x37b8 => 'IOError',
    0x39df => 'PermissionError',
    0x39e6 => 'AttributeError',
    0x3b70 => 'ChildProcessError',
    0x3c93 => 'UserWarning',
    0x3ca3 => 'BufferError',
    0x3e32 => 'StopIteration',
    0x423c => 'NotADirectoryError',
    0x42f1 => 'ConnectionError',
    0x453b => 'UnboundLocalError',
    0x470d => 'LookupError',
    0x4cb2 => 'WindowsError',
    0x4ecc => 'ResourceWarning',
    0x532d => 'UnicodeEncodeError',
    0x5dde => 'ConnectionAbortedError',
    0x6011 => 'EOFError',
    0x637f => 'UnicodeWarning',
    0x6482 => 'RuntimeError',
    0x6a75 => 'ArithmeticError',
    0x6b73 => 'BlockingIOError',
    0x70e0 => 'UnicodeDecodeError',
    0x72b4 => 'AssertionError',
    0x75a1 => 'TabError',
    0x77c2 => 'ReferenceError',
    0x7a4c => 'FutureWarning',
    0x7a78 => 'Warning',
    0x7ef9 => 'IsADirectoryError',
    0x81dc => 'ConnectionResetError',
    0x87fa => 'OSError',
    0x8937 => 'KeyError',
    0x8a80 => 'SyntaxError',
    0x8f3e => 'TypeError',
    0x9329 => 'MemoryError',
    0x956e => 'ValueError',
    0x96a1 => 'OverflowError',
    0xa451 => 'InterruptedError',
    0xa4d7 => 'FileExistsError',
    0xb19a => 'ZeroDivisionError',
    0xb27b => 'IndexError',
    0xb628 => 'UnicodeError',
    0xbb63 => 'TimeoutError',
    0xbc91 => 'ImportWarning',
    0xc18f => 'BrokenPipeError',
    0xc3a0 => 'KeyboardInterrupt',
    0xcbab => 'ImportError',
    0xcd47 => 'NameError',
    0xcd82 => 'ProcessLookupError',
    0xdd4a => 'BaseException',
    0xe5a3 => 'BytesWarning',
    0xe97a => 'FileNotFoundError',
    0xe98a => 'PendingDeprecationWarning',
    0xf47c => 'DeprecationWarning',
    0xf7c6 => 'Exception',
    0xfa9d => 'EnvironmentError',
    0xfcb4 => 'UnicodeTranslateError',
    0xff8d => 'FloatingPointError'
  }

  def initialize(rstream, opts={})
    super
    self.base_platform = 'python'
    self.base_arch = ARCH_PYTHON
  end

  def lookup_error(error_code)
    unknown_error = 'Unknown error'
    error_type = error_code & 0x0f
    return unknown_error if error_type == ERROR_TYPE_UNKNOWN

    error_code &= 0xffff0000
    error_code >>= 16

    if error_type == ERROR_TYPE_PYTHON
      python_error = PYTHON_ERROR_CRCS[error_code]
      return "Python exception: #{python_error}" unless python_error.nil?
    elsif error_type == ERROR_TYPE_WINDOWS
      return "Windows error: #{Msf::WindowsError.description(error_code)}"
    end

    unknown_error
  end

  def native_arch
    @native_arch ||= self.core.native_arch
  end

  def supports_ssl?
    false
  end

  def supports_zlib?
    false
  end
end

end
end
