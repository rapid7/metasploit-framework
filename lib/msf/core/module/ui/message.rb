# Methods for print messages with status indicators
module Msf::Module::UI::Message
  autoload :Verbose, 'msf/core/module/ui/message/verbose'

  include Msf::Module::UI::Message::Verbose

  def print_error(msg='')
    super(print_prefix + msg)
  end

  alias_method :print_bad, :print_error

  def print_good(msg='')
    super(print_prefix + msg)
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
    prefix
  end

  def print_status(msg='')
    super(print_prefix + msg)
  end

  def print_warning(msg='')
    super(print_prefix + msg)
  end
end
