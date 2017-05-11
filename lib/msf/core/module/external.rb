module Msf::Module::External
  def wait_status(mod)
    while mod.running
      m = mod.get_status
      if m
        case m['level']
        when 'error'
          print_error m['message']
        when 'warning'
          print_warning m['message']
        when 'good'
          print_good m['message']
        when 'info'
          print_status m['message']
        when 'debug'
          vprint_status m['message']
        else
          print_status m['message']
        end
      end
    end
  end
end
