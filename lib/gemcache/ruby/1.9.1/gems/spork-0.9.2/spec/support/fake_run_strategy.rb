class FakeRunStrategy < Spork::RunStrategy
  def initialize(*args)
  end

  def self.available?
    true
  end

  def run(argv, stderr, stdout)
    sleep(@wait_time || 0.5)
    true
  end

  def running?
    false
  end

  def preload
    true
  end
end
