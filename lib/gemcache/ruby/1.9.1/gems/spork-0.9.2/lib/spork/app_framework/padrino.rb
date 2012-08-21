class Spork::AppFramework::Padrino < Spork::AppFramework
  
  def preload(&block)
    STDERR.puts "Preloading Padrino environment"
    STDERR.flush
    ENV["PADRINO_ENV"] ||= "test"
    require boot_file
    # Make it so that we don't have to restart Spork if we change, say, a model or routes
    Spork.each_run { ::Padrino.reload! }
    yield
  end
  
  def entry_point
    @entry_point ||= File.expand_path("config/boot.rb", Dir.pwd)
  end
  alias :boot_file :entry_point
  
  def boot_contents
    @boot_contents ||= File.read(boot_file)
  end
  
end