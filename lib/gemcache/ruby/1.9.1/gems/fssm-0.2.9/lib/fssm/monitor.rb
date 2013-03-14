class FSSM::Monitor
  def initialize(options={})
    @options = options
    @backend = FSSM::Backends::Default.new
  end

  def path(path=nil, glob=nil, &block)
    path = create_path(path, glob, &block)
    @backend.add_handler(FSSM::State::Directory.new(path, @options))
    path
  rescue FSSM::FileNotRealError => e
    FSSM.dbg("#{e}")
    nil
  end

  def file(path=nil, glob=nil, &block)
    path = create_path(path, glob, &block)
    @backend.add_handler(FSSM::State::File.new(path))
    path
  rescue FSSM::FileNotRealError => e
    FSSM.dbg("#{e}")
    nil
  end

  def run
    @backend.run
  end

  private

  def create_path(path, glob, &block)
    path = FSSM::Path.new(path, glob, @options)
    FSSM::Support.use_block(path, block)
    path
  end
end
