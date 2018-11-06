unless Proc.method_defined? :curry
  require 'backports/1.9.1/proc/lambda'

  class Proc
    def curry(argc = nil)
      min_argc = arity < 0 ? -arity - 1 : arity
      argc ||= min_argc
      if lambda? and arity < 0 ? argc < min_argc : argc != arity
        raise ArgumentError, "wrong number of arguments (#{argc} for #{min_argc})"
      end
      creator = lambda? ? :lambda : :proc
      block = send(creator) do |*args|
        if args.size >= argc
          call(*args)
        else
          send(creator) do |*more_args|
            args += more_args
            block.call(*args)
          end
        end
      end
    end
  end
end
