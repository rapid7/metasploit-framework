# Picks up all the protocols defined in the protos subdirectory
path = File.expand_path(File.join(File::dirname(__FILE__), "protos", "*.rb"))
Dir.glob(path).each do |file|
  require file
end
