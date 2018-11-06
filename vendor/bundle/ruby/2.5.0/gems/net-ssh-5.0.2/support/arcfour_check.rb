
require 'net/ssh'

# ARCFOUR CHECK 
# 
# Usage:
#     $ ruby support/arcfour_check.rb
#
# Expected Output:
#     arcfour128: [16, 8] OpenSSL::Cipher::Cipher
#     arcfour256: [32, 8] OpenSSL::Cipher::Cipher
#     arcfour512: [64, 8] OpenSSL::Cipher::Cipher

[['arcfour128', 16], ['arcfour256', 32], ['arcfour512', 64]].each do |cipher|
  print "#{cipher[0]}: "
  a = Net::SSH::Transport::CipherFactory.get_lengths(cipher[0])
  b = Net::SSH::Transport::CipherFactory.get(cipher[0], key: ([].fill('x', 0, cipher[1]).join))
  puts "#{a} #{b.class}"
end

