#!/usr/bin/env ruby
# Decrypts the meterpreter.php from the installed metasploit-payloads gem,
# applies the TCP EOF fix for both socket and stream channel types,
# re-encrypts, and writes it back.
#
# Usage: bundle exec ruby .github/patches/patch_php_meterpreter.rb

require 'metasploit-payloads'

gem_path = `bundle show metasploit-payloads`.strip
target   = File.join(gem_path, 'data', 'meterpreter', 'meterpreter.php')

puts "Patching: #{target}"

plaintext = MetasploitPayloads::Crypto.decrypt(ciphertext: File.binread(target))
patched   = plaintext.dup

# Fix 1: socket case - socket_read returns "" or false on peer close
patched = patched.sub(
  /^( +my_print\("Reading TCP socket"\);\n +)\$buff \.= socket_read\(\$resource, \$len, PHP_BINARY_READ\);(\n)/
) do
  $~[1] +
  "$result = socket_read($resource, $len, PHP_BINARY_READ);\n" \
  "      # socket_read returns \"\" or false when the peer closes the connection.\n" \
  "      if ($result === false || $result === '') {\n" \
  "        $buff = false;\n" \
  "      } else {\n" \
  "        $buff .= $result;\n" \
  "      }" +
  $~[2]
end

abort('ERROR: fix 1 (socket EOF) did not apply') if patched == plaintext

# Fix 2: stream case - fread returns "" on peer close when unread_bytes == 0.
# No msgsock guard needed: the C2 socket always has unread_bytes > 0 when
# stream_select fires for it, so it never hits this else branch.
before_fix2 = patched.dup
patched = patched.sub(
  /^( +\$tmp = fread\(\$resource, \$len\);\n +\$last_requested_len = \$len;\n)/
) do
  $~[1] +
  "        # An empty fread on a stream that stream_select reported as readable\n" \
  "        # means the peer has closed the connection (EOF). feof() may not return\n" \
  "        # true immediately on all stream types (e.g. SSL), so treat \"\" as EOF.\n" \
  "        if ($tmp === false || $tmp === '') {\n" \
  "          if (empty($buff)) {\n" \
  "            $buff = false;\n" \
  "          }\n" \
  "          break;\n" \
  "        }\n"
end

abort('ERROR: fix 2 (stream EOF) did not apply') if patched == before_fix2

File.binwrite(target, MetasploitPayloads::Crypto.encrypt(plaintext: patched))
puts 'meterpreter.php patched successfully (socket + stream EOF fixes applied)'
