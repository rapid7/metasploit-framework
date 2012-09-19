class FSSM::Path
  def initialize(path=nil, glob=nil, options={}, &block)
    @options = options
    set_path(path || '.')
    set_glob(glob || '**/*')
    init_callbacks

    if block_given?
      if block.arity == 1
        block.call(self)
      else
        self.instance_eval(&block)
      end
    end
  end

  def to_s
    @path.to_s
  end

  def to_pathname
    @path
  end

  def glob(value=nil)
    return @glob if value.nil?
    set_glob(value)
  end

  def create(*args, &block)
    callback_action(:create, (block_given? ? block : args))
  end

  def update(*args, &block)
    callback_action(:update, (block_given? ? block : args))
  end

  def delete(*args, &block)
    callback_action(:delete, (block_given? ? block : args))
  end

  private

  def init_callbacks
    do_nothing = lambda { |base, relative|}
    @callbacks = Hash.new(do_nothing)
  end

  def callback_action(type, args=[])
    if args.is_a?(Proc)
      set_callback(type, args)
    elsif args.empty?
      get_callback(type)
    else
      run_callback(type, args)
    end
  end

  def set_callback(type, arg)
    raise ArgumentError, "Proc expected" unless arg.is_a?(Proc)
    @callbacks[type] = arg
  end

  def get_callback(type)
    @callbacks[type]
  end

  def run_callback(type, args)
    callback_args = split_path(args[0])
    callback_args << args[1] if @options[:directories]

    begin
      @callbacks[type].call(*callback_args)
    rescue Exception => e
      raise FSSM::CallbackError, "#{type} - #{args[0]}: #{e.message}", e.backtrace
    end
  end

  def split_path(path)
    path = FSSM::Pathname.for(path)
    [@path.to_s, (path.relative? ? path : path.relative_path_from(@path)).to_s]
  end

  def set_path(path)
    @path = FSSM::Pathname.for(path).expand_path
    raise FSSM::FileNotFoundError, "No such file or directory - #{@path}" unless @path.exist?
    raise FSSM::FileNotRealError, "Path is virtual - #{@path}" if @path.is_virtual?
    @path = @path.realpath
  end

  def set_glob(glob)
    @glob = glob.is_a?(Array) ? glob : [glob]
  end
end
