# Load the rails application
require File.expand_path('../application', __FILE__)

# Initialize the rails application
begin
  Metasploit::Framework::Application.initialize!
rescue Exception, Errno::ENOENT => e
  $stderr.puts "[!] WARNING, the Metasploit Framework Application threw an exception:"
  $stderr.puts "[!] #{e.inspect}"
  $stderr.puts "[!] Try running with '-n' (no database)"
end
