#!/usr/bin/ruby

# SSH TUNNEL CONNECTION BUG
# from: http://net-ssh.lighthouseapp.com/projects/36253/tickets/7-an-existing-connection-was-forcibly-closed-by-the-remote-host#ticket-7-3
#
# Steps to reproduce:
#
# * Start HTTP Proxy
#   * If running debian in EC2:
#     * apt-get install squid
#     * Add the following to /etc/squid/squid.conf:
#       acl localnet src 1.2.3.0/255.255.255.0
#       http_access allow  localnet
#       icp_access  allow  localnet
#       visible_hostname netsshtest
#     * Start squid squid -N -d 1 -D
# * Run this script
# * Configure browser proxy to use localhost with LOCAL_PORT. 
# * Load any page, wait for it to load fully. If the page loads
#   correctly, move on. If not, something needs to be corrected.
# * Refresh the page several times. This should cause this
#   script to failed with the error: "closed stream". You may
#   need to try a few times. 
#

require 'highline/import'
require 'net/ssh'

LOCAL_PORT = 8080
PROXY_PORT = 3128

host, user = *ARGV
abort "Usage: #{$0} host user" unless ARGV.size == 2

puts "Connecting to #{user}@#{host}..."
pass = ask("Password: ") { |q| q.echo = "*" }
puts "Configure your browser proxy to localhost:#{LOCAL_PORT}"

begin
  session = Net::SSH.start(host, user, password: pass)  
  session.forward.local(LOCAL_PORT, host, PROXY_PORT)
  session.loop {true}
rescue StandardError => e
  puts e.message
  puts e.backtrace
end


__END__

$ ruby support/ssh_tunnel.rb host user
Connecting to user@host...
Password: ******
Configure your browser proxy to localhost:8080
closed stream
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/buffered_io.rb:99:in `send'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/buffered_io.rb:99:in `send_pending'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:236:in `block in postprocess'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:235:in `each'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:235:in `postprocess'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:203:in `process'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:161:in `block in loop'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:161:in `loop'
/usr/local/lib/ruby/gems/1.9.1/gems/net-ssh-2.0.15/lib/net/ssh/connection/session.rb:161:in `loop'

