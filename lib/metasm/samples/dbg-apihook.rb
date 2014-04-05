#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# This sample defines an ApiHook class, that you can subclass to easily hook functions
# in a debugged process. Your custom function will get called whenever an API function is,
# giving you access to the arguments, you can also take control just before control returns
# to the caller.
# See the example in the end for more details.
# As a standalone application, it hooks WriteFile in the 'notepad' process, and make it
# skip the first two bytes of the buffer.
#

require 'metasm'

class ApiHook
  attr_accessor :dbg

  # rewrite this function to list the hooks you want
  # return an array of hashes
  def setup
    #[{ :function => 'WriteFile', :abi => :stdcall },	# standard function hook
    # { :module => 'Foo.dll', :rva => 0x2433,		# arbitrary code hook
    #   :abi => :fastcall, :hookname => 'myhook' }]		# hooks named pre_myhook/post_myhook
  end

  # initialized from a Debugger or a process description that will be debugged
  # sets the hooks up, then run_forever
  def initialize(dbg)
    if not dbg.kind_of? Metasm::Debugger
      process = Metasm::OS.current.find_process(dbg)
      raise 'no such process' if not process
      dbg = process.debugger
    end
    @dbg = dbg
    begin
      setup.each { |h| setup_hook(h) }
      init_prerun if respond_to?(:init_prerun)	# allow subclass to do stuff before main loop
      @dbg.run_forever
    rescue Interrupt
      @dbg.detach #rescue nil
    end
  end

  # setup one function hook
  def setup_hook(h)
    @las ||= false
    if not h[:lib] and not @las
      @dbg.loadallsyms
      @las = false
    elsif h[:lib]
      # avoid loadallsyms if specified (regexp against pathname, not exported lib name)
      @dbg.loadsyms(h[:lib])
    end

    pre  =  "pre_#{h[:hookname] || h[:function]}"
    post = "post_#{h[:hookname] || h[:function]}"

    nargs = h[:nargs] || method(pre).arity if respond_to?(pre)

    if target = h[:address]
    elsif target = h[:rva]
      modbase = @dbg.modulemap[h[:module]]
      raise "cant find module #{h[:module]} in #{@dbg.modulemap.join(', ')}" if not modbase
      target += modbase[0]
    else
      target = h[:function]
    end

    @dbg.bpx(target, false, h[:condition]) {
      @nargs = nargs
      catch(:finish) {
        @cur_abi = h[:abi]
        @ret_longlong = h[:ret_longlong]
        if respond_to? pre
          args = read_arglist
          send pre, *args
        end
        if respond_to? post
          @dbg.bpx(@dbg.func_retaddr, true) {
            retval = read_ret
            send post, retval, args
          }
        end
      }
    }
  end

  # retrieve the arglist at func entry, from @nargs & @cur_abi
  def read_arglist
    nr = @nargs
    args = []

    if (@cur_abi == :fastcall or @cur_abi == :thiscall) and nr > 0
      args << @dbg.get_reg_value(:ecx)
      nr -= 1
    end

    if @cur_abi == :fastcall and nr > 0
      args << @dbg.get_reg_value(:edx)
      nr -= 1
    end

    nr.times { |i| args << @dbg.func_arg(i) }

    args
       	end

  # retrieve the function returned value
  def read_ret
    ret = @dbg.func_retval
    if @ret_longlong
      ret = (ret & 0xffffffff) | (@dbg[:edx] << 32)
    end
    ret
  end

  # patch the value of an argument
  # only valid in pre_hook
  # nr starts at 0
  def patch_arg(nr, value)
    case @cur_abi
    when :fastcall
      case nr
      when 0
        @dbg.set_reg_value(:ecx, value)
        return
      when 1
        @dbg.set_reg_value(:edx, value)
        return
      else
        nr -= 2
      end
    when :thiscall
      case nr
      when 0
        @dbg.set_reg_value(:ecx, value)
        return
      else
        nr -= 1
      end
    end

    @dbg.func_arg_set(nr, value)
  end

  # patch the function return value
  # only valid post_hook
  def patch_ret(val)
    if @ret_longlong
      @dbg.set_reg_value(:edx, (val >> 32) & 0xffffffff)
      val &= 0xffffffff
    end
    @dbg.func_retval_set(val)
  end

  # skip the function call
  # only valid in pre_hook
  def finish(retval)
    patch_ret(retval)
    @dbg.ip = @dbg.func_retaddr
    case @cur_abi
    when :fastcall
      @dbg[:esp] += 4*(@nargs-2) if @nargs > 2
    when :thiscall
      @dbg[:esp] += 4*(@nargs-1) if @nargs > 1
    when :stdcall
      @dbg[:esp] += 4*@nargs
    end
    @dbg.sp += @dbg.cpu.size/8
    throw :finish
  end
end



if __FILE__ == $0

# this is the class you have to define to hook
# 
# setup() defines the list of hooks as an array of hashes
# for exported functions, simply use :function => function name
# for arbitrary hook, :module => 'module.dll', :rva => 0x1234, :hookname => 'myhook' (call pre_myhook/post_myhook)
# :abi can be :stdcall (windows standard export), :fastcall or :thiscall, leave empty for cdecl
# if pre_<function> is defined, it is called whenever the function is entered, via a bpx (int3)
# if post_<function> is defined, it is called whenever the function exists, with a bpx on the return address setup at func entry
# the pre_hook receives all arguments to the original function
#  change them with patch_arg(argnr, newval)
#  read memory with @dbg.memory_read_int(ptr), or @dbg.memory[ptr, length]
#  skip the function call with finish(fake_retval) (!) needs a correct :abi & param count !
# the post_hook receives the function return value
#  change it with patch_ret(newval)
class MyHook < ApiHook
  def setup
    [{ :function => 'WriteFile', :abi => :stdcall }]
  end

  def init_prerun
    puts "hooks ready, save a file in notepad"
  end

  def pre_WriteFile(handle, pbuf, size, pwritten, overlap)
    # we can skip the function call with this
    #finish(28)

    # spy on the api / trace calls
    bufdata = @dbg.memory[pbuf, size]
    puts "writing #{bufdata.inspect}"

    # but we can also mess with the args
    # ex: skip first 2 bytes of the buffer
    patch_arg(1, pbuf+2)
    patch_arg(2, size-2)
  end

  def post_WriteFile(retval, arglistcopy)
    # we can patch the API return value with this
    #patch_retval(42)

    # finish messing with the args: fake the nrofbyteswritten
    #handle, pbuf, size, pwritten, overlap = arglistcopy
    size, pwritten = arglistcopy.values_at(2, 3)
    written = @dbg.memory_read_int(pwritten)
    if written == size
      # if written everything, patch the value so that the program dont detect our intervention
      @dbg.memory_write_int(pwritten, written+2)
    end

    puts "write retval: #{retval}, written: #{written} bytes"
  end
end

Metasm::OS.current.get_debug_privilege if Metasm::OS.current.respond_to? :get_debug_privilege

# run our Hook engine on a running 'notepad' instance
MyHook.new('notepad')

# the script ends when notepad exits

end
