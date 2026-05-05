# Methods for print messages with status indicators
module Msf::Module::UI::Message
  autoload :Verbose, 'msf/core/module/ui/message/verbose'

  include Msf::Module::UI::Message::Verbose

  def print_error(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(msg_prefix + strip_peer_prefix(msg_prefix, msg))
  end

  alias_method :print_bad, :print_error

  def print_good(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(msg_prefix + strip_peer_prefix(msg_prefix, msg))
  end

  def print_prefix
    prefix = ''
    if datastore['TimestampOutput'] ||
        (framework && framework.datastore['TimestampOutput'])
      prefix << "[#{Time.now.strftime("%Y.%m.%d-%H:%M:%S")}] "

      xn ||= datastore['ExploitNumber']
      xn ||= framework.datastore['ExploitNumber']
      if xn.is_a?(Integer)
        prefix << "[%04d] " % xn
      end
    end

    if (module_name_output = (datastore['ModuleNameOutput'] ||
        (framework && framework.datastore['ModuleNameOutput'])))
      prefix << "[#{module_name_output}] "
    end
    prefix
  end

  def print_status(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(msg_prefix + strip_peer_prefix(msg_prefix, msg))
  end

  def print_warning(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(msg_prefix + strip_peer_prefix(msg_prefix, msg))
  end

  private

  # When print_prefix already contains a peer address (e.g. injected by Msf::Exploit::Remote::Tcp),
  # strip that same address from the start of msg to avoid it appearing twice in the output
  def strip_peer_prefix(msg_prefix, msg)
    # IPv4 address (e.g. 127.0.0.1:yy)
    if (m = msg_prefix.match(/(\d+\.\d+\.\d+\.\d+:\d+)/))
      msg.to_s.sub(/\A#{Regexp.escape(m[1])}\s*-\s*/, '')
    # IPv6 address (e.g. [::1]:yy    ::1:yy)
    elsif (m = msg_prefix.match(/\[([\da-fA-F:]+)\]:(\d+)/))
      msg.to_s.sub(/\A(?:\[#{Regexp.escape(m[1])}\]|#{Regexp.escape(m[1])}):#{m[2]}\s*-\s*/, '')
    else
      msg
    end
  end
end
