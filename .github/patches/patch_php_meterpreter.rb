#!/usr/bin/env ruby
# Decrypts the meterpreter.php from the installed metasploit-payloads gem,
# applies the TCP EOF fix, re-encrypts, and writes it back.
#
# Usage: bundle exec ruby .github/patches/patch_php_meterpreter.rb

require 'metasploit-payloads'

gem_path = `bundle show metasploit-payloads`.strip
target   = File.join(gem_path, 'data', 'meterpreter', 'meterpreter.php')

puts "Patching: #{target}"

plaintext = MetasploitPayloads::Crypto.decrypt(ciphertext: File.binread(target))

patched = plaintext.sub(
  /^( +\$tmp = fread\(\$resource, \$len\);\n +\$last_requested_len = \$len;\n)/
) do
  $~[1] +
  "        if ($tmp === false || ($tmp === '' && $resource !== $msgsock)) {\n" \
  "          if (empty($buff)) {\n" \
  "            $buff = false;\n" \
  "          }\n" \
  "          break;\n" \
  "        }\n"
end

abort('ERROR: patch did not apply - pattern not found in meterpreter.php') if patched == plaintext

File.binwrite(target, MetasploitPayloads::Crypto.encrypt(plaintext: patched))
puts 'meterpreter.php patched successfully'
