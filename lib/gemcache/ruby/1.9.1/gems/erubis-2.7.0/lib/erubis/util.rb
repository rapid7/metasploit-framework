##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

module Kernel

  ##
  ## raise NotImplementedError
  ##
  def not_implemented     #:doc:
    backtrace = caller()
    method_name = (backtrace.shift =~ /`(\w+)'$/) && $1
    mesg = "class #{self.class.name} must implement abstract method '#{method_name}()'."
    #mesg = "#{self.class.name}##{method_name}() is not implemented."
    err = NotImplementedError.new mesg
    err.set_backtrace backtrace
    raise err
  end
  private :not_implemented

end
