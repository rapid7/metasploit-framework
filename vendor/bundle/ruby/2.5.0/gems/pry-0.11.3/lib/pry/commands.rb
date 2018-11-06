# Default commands used by Pry.
Pry::Commands = Pry::CommandSet.new

Dir[File.expand_path('../commands', __FILE__) << '/*.rb'].each do |file|
  require file
end
