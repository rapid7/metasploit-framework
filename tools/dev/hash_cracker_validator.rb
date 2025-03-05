#!/usr/bin/env ruby

# This script is used to validate the hash cracking capabilities of metasploit
# https://github.com/rapid7/metasploit-framework/pull/17667 shows the complexity
# of trying to insert hashes, run the appropriate hash cracking module, and verify the hashes are cracked.
# this automates everything and checks the output of the hash cracking modules to ensure they are working as expected
# author: h00die

require 'open3'
require 'tempfile'
require 'optparse'

options = { test: 'all', verbose: false }

OptionParser.new do |opts|
  opts.banner = <<~BANNER
    hash_cracker_validator.rb - A Script to verify hash cracking in Metasploit.

    Based on passwords/hashes from https://docs.metasploit.com/docs/using-metasploit/intermediate/hashes-and-password-cracking.html#hashes

    Usage: hash_cracker_validator.rb [options]
  BANNER
  opts.on('--verbose', 'Enable verbose output.') do
    options[:verbose] = true
  end
  opts.on('-t', '--test LIST', "Which tests to conduct. Takes a list of numbers (comma-separated), defaults to 'all'",
          'Test 1: Test database connection',
          'Test 2: *nix     hashes in john wordlist mode',
          'Test 3: windows  hashes in john wordlist mode',
          'Test 4: sql      hashes in john wordlist mode',
          'Test 5: osx      hashes in john wordlist mode',
          'Test 6: webapp   hashes in john wordlist mode',
          'Test 7: *nix     hashes in hashcat wordlist mode',
          'Test 8: windows  hashes in hashcat wordlist mode',
          'Test 9: sql      hashes in hashcat wordlist mode',
          'Test 10: mobile  hashes in hashcat wordlist mode',
          'Test 11: osx     hashes in hashcat wordlist mode',
          'Test 12: webapp  hashes in hashcat wordlist mode',
          'Test 13: *nix    hashes in john pot mode',
          'Test 14: windows hashes in john pot mode',
          'Test 15: sql     hashes in john pot mode',
          'Test 16: osx     hashes in john pot mode',
          'Test 17: webapp  hashes in john pot mode',
          'Test 18: *nix    hashes in hashcat pot mode',
          'Test 19: windows hashes in hashcat pot mode',
          'Test 20: sql    hashes in hashcat pot mode',
          'Test 21: mobile hashes in hashcat pot mode',
          'Test 22: osx    hashes in hashcat pot mode',
          'Test 23: webapp hashes in hashcat pot mode',
          'Test 24: all    hashes in john apply_pot mode') do |list|
    options[:test] = begin
      list.split(',').map(&:strip).map(&:to_i)
    rescue StandardError
      'all'
    end
  end
end.parse!

# colors and puts templates from msftidy.rb

class String
  def red
    "\e[1;31;40m#{self}\e[0m"
  end

  def yellow
    "\e[1;33;40m#{self}\e[0m"
  end

  def green
    "\e[1;32;40m#{self}\e[0m"
  end

  def cyan
    "\e[1;36;40m#{self}\e[0m"
  end
end

def cleanup_text(txt)
  txt
end

#
# Display an error message, given some text
#
def good(txt)
  puts "[#{'GOOD'.green}] #{cleanup_text(txt)}"
end

#
# Display an error message, given some text
#
def error(txt)
  puts "[#{'ERROR'.red}] #{cleanup_text(txt)}"
end

#
# Display a warning message, given some text
#
def warning(txt)
  puts "[#{'WARNING'.yellow}] #{cleanup_text(txt)}"
end

#
# Display a info message, given some text
#
def info(txt)
  puts "[#{'INFO'.cyan}] #{cleanup_text(txt)}"
end

warning 'WARNING: All credentials will be deleted as part of this script execution!'

start_time = Time.now

def run_msfconsole(command, expected_output_regexes)
  section_start_time = Time.now
  stdout, stderr = Open3.capture3("./msfconsole --defer-module-loads -qx \"#{command}\"")

  failing_regex = expected_output_regexes.find { |regex| !stdout.match?(regex) }

  if failing_regex.nil?
    good '  SUCCESS: All expected outputs found.'
    good "  Section Runtime: #{Time.now - section_start_time} seconds"
    return true
  else
    error "  FAILURE: Expected output not found for regex: #{failing_regex.inspect}"
    error "  STDOUT: #{stdout}"
    error "  Section Runtime: #{Time.now - section_start_time} seconds"
    error "  STDERR: #{stderr}"
    return false
  end
end

if options[:test] == 'all' || options[:test].include?(1)
  info '[1/24] Checking Metasploit database connection...'
  db_status_command = 'db_status; exit'
  db_expected_output_regex = [/Connected to .+\. Connection type: .+\./]
  unless run_msfconsole(db_status_command, db_expected_output_regex)
    puts '-------------------------------'
    error 'Database connection check failed. Exiting.'
    exit 1
  end
end

wordlist = Tempfile.new('wordlist')
File.open(wordlist, 'w') { |file| file.write("password\nhashcat\ntest1\ntoto\nfoo\nPassword1!\nprobe\ntere\na\nTHALES\nepsilon\n1234\nTestPass123#\npasswor\nd\n") }
info "Wordlist file created at: #{wordlist.path}"

if options[:test] == 'all' || options[:test].include?(2)
  info '[2/24] Running *nix hashes in john wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:des_password hash:rEK1ecacw.7.c jtr:des;'
  creds_expected_output_regex << /des_password\s+rEK1ecacw\.7\.c\s+Nonreplayable hash\s+des\s+password$/
  creds_command << ' creds add user:md5_password hash:\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5;'
  creds_expected_output_regex << %r{md5_password\s+\$1\$O3JMY\.Tw\$AdLnLjQ/5jXF9\.MTp3gHv/\s+Nonreplayable hash\s+md5\s+password$}
  creds_command << ' creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi;'
  creds_expected_output_regex << /bsdi_password\s+_J9\.\.K0AyUubDrfOgO4s\s+Nonreplayable hash\s+bsdi\s+password$/
  creds_command << ' creds add user:sha256_password hash:\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt;'
  creds_command << ' set SHA256 true;'
  creds_expected_output_regex << %r{sha256_password\s+\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP\.Os80yXhTurpBMUbA5\s+Nonreplayable hash\s+sha256,crypt\s+password$}
  creds_command << ' creds add user:sha512_password hash:\$6\$zWwwXKNj\$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt;'
  creds_command << ' set SHA512 true;'
  creds_expected_output_regex << %r{sha512_password\s+\$6\$zWwwXKNj\$gLAOoZCjcr8p/\.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcV \(TRUNCATED\)\s+Nonreplayable hash\s+sha512,crypt\s+password$}
  creds_command << ' creds add user:blowfish_password hash:\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf;'
  creds_command << ' set BLOWFISH true;'
  creds_expected_output_regex << %r{blowfish_password\s+\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe\s+Nonreplayable hash\s+bf\s+password$}
  creds_command << ' use auxiliary/analyze/crack_linux;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(3)
  info '[3/24] Running windows hashes in john wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm;'
  creds_expected_output_regex << /lm_password\s+e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt;'
  creds_expected_output_regex << /nt_password\s+aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:u4-netntlm hash:u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c jtr:netntlm;'
  creds_expected_output_regex << /u4-netntlm\s+u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a \(TRUNCATED\)\s+Nonreplayable hash\s+netntlm\s+hashcat$/
  creds_command << ' creds add user:admin hash:admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 jtr:netntlmv2;'
  creds_expected_output_regex << /admin\s+admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c783031 \(TRUNCATED\)\s+Nonreplayable hash\s+netntlmv2\s+hashcat$/
  creds_command << ' creds add user:mscash-test1 hash:M\$test1#64cd29e36a8431a2b111378564a10631 jtr:mscash;'
  creds_expected_output_regex << /mscash-test1\s+M\$test1\#64cd29e36a8431a2b111378564a10631\s+Nonreplayable hash\s+mscash\s+test1$/
  creds_command << ' creds add user:mscash2-hashcat hash:\$DCC2\$10240#tom#e4e938d12fe5974dc42a90120bd9c90f jtr:mscash2;'
  creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_windows;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(4)
  info '[4/24] Running sql hashes in john wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05;'
  creds_expected_output_regex << /mssql05_toto\s+0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908\s+Nonreplayable hash\s+mssql05\s+toto$/
  creds_command << ' creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql;'
  creds_expected_output_regex << /mssql_foo\s+0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6 \(TRUNCATED\)\s+Nonreplayable hash\s+mssql\s+FOO$/
  creds_command << ' creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12;'
  creds_expected_output_regex << /mssql12_Password1!\s+0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE \(TRUNCATED\)\s+Nonreplayable hash\s+mssql12\s+Password1!$/
  creds_command << ' creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql;'
  creds_expected_output_regex << /mysql_probe\s+445ff82636a7ba59\s+Nonreplayable hash\s+mysql\s+probe$/
  creds_command << ' creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1;'
  creds_expected_output_regex << /mysql-sha1_tere\s+\*5AD8F88516BD021DD43F171E2C785C69F8E54ADB\s+Nonreplayable hash\s+mysql-sha1\s+tere$/
  creds_command << ' creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle;'
  creds_expected_output_regex << /simon\s+4F8BC1809CB2AF77\s+Nonreplayable hash\s+des,oracle\s+A$/
  creds_command << ' creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle;'
  creds_expected_output_regex << /SYSTEM\s+9EEDFA0AD26C6D52\s+Nonreplayable hash\s+des,oracle\s+THALES$/
  # can't escape ;?
  # creds_command << ' creds add user:DEMO hash:\'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C\' jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle11_epsilon hash:"S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A\\\\;H:DC9894A01797D91D92ECA1DA66242209\\\\;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C" jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle12c_epsilon hash:"H:DC9894A01797D91D92ECA1DA66242209\\\\;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B" jtr:pbkdf2,oracle12c;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860;'
  # creds_expected_output_regex << /example\s+md5be86a79bf2043622d58d5453c47d4860\s+Postgres md5\s+raw-md5,postgres\s+password$/

  creds_command << ' use auxiliary/analyze/crack_databases;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(5)
  info '[5/24] Running osx hashes in john wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:xsha_hashcat hash:1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683 jtr:xsha;'
  creds_expected_output_regex << /xsha_hashcat\s+1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683\s+Nonreplayable hash\s+xsha\s+hashcat$/
  creds_command << ' creds add user:pbkdf2_hashcat hash:\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222 jtr:PBKDF2-HMAC-SHA512;'
  creds_expected_output_regex << /pbkdf2_hashcat\s+\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$7 \(TRUNCATED\)\s+Nonreplayable hash\s+PBKDF2-HMAC-SHA512\s+hashcat$/
  creds_command << ' creds add user:xsha512_hashcat hash:648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d jtr:xsha512;'
  creds_expected_output_regex << /xsha512_hashcat\s+648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c0 \(TRUNCATED\)\s+Nonreplayable hash\s+xsha512\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_osx;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(6)
  info '[6/24] Running webapp hashes in john wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:mediawiki_hashcat hash:\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898 jtr:mediawiki;'
  creds_expected_output_regex << /mediawiki_hashcat\s+\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898\s+Nonreplayable hash\s+mediawiki\s+hashcat$/
  creds_command << ' creds add user:phpass_p_hashcat hash:\$P\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_p_hashcat\s+\$P\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:phpass_h_hashcat hash:\$H\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_h_hashcat\s+\$H\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:atlassian_hashcat hash:{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa jtr:PBKDF2-HMAC-SHA1;'
  creds_expected_output_regex << %r{atlassian_hashcat\s+\{PKCS5S2\}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa\s+Nonreplayable\s+hash\s+PBKDF2-HMAC-SHA1\s+hashcat$}
  creds_command << ' use auxiliary/analyze/crack_webapps;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(7)
  info '[7/24] Running *nix hashes in hashcat wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:des_password hash:rEK1ecacw.7.c jtr:des;'
  creds_expected_output_regex << /des_password\s+rEK1ecacw\.7\.c\s+Nonreplayable hash\s+des\s+password$/
  creds_command << ' creds add user:md5_password hash:\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5;'
  creds_expected_output_regex << %r{md5_password\s+\$1\$O3JMY\.Tw\$AdLnLjQ/5jXF9\.MTp3gHv/\s+Nonreplayable hash\s+md5\s+password$}
  creds_command << ' creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi;'
  creds_expected_output_regex << /bsdi_password\s+_J9\.\.K0AyUubDrfOgO4s\s+Nonreplayable hash\s+bsdi\s+password$/
  creds_command << ' creds add user:sha256_password hash:\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt;'
  creds_command << ' set SHA256 true;'
  creds_expected_output_regex << %r{sha256_password\s+\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP\.Os80yXhTurpBMUbA5\s+Nonreplayable hash\s+sha256,crypt\s+password$}
  creds_command << ' creds add user:sha512_password hash:\$6\$zWwwXKNj\$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt;'
  creds_command << ' set SHA512 true;'
  creds_expected_output_regex << %r{sha512_password\s+\$6\$zWwwXKNj\$gLAOoZCjcr8p/\.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcV \(TRUNCATED\)\s+Nonreplayable hash\s+sha512,crypt\s+password$}
  creds_command << ' creds add user:blowfish_password hash:\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf;'
  creds_command << ' set BLOWFISH true;'
  creds_expected_output_regex << %r{blowfish_password\s+\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe\s+Nonreplayable hash\s+bf\s+password$}
  creds_command << ' use auxiliary/analyze/crack_linux;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(8)
  info '[8/24] Running windows hashes in hashcat wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm;'
  creds_expected_output_regex << /lm_password\s+e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+PASSWORD$/
  creds_command << ' creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt;'
  creds_expected_output_regex << /nt_password\s+aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:u4-netntlm hash:u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c jtr:netntlm;'
  creds_expected_output_regex << /u4-netntlm\s+u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a \(TRUNCATED\)\s+Nonreplayable hash\s+netntlm\s+hashcat$/
  creds_command << ' creds add user:admin hash:admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 jtr:netntlmv2;'
  creds_expected_output_regex << /admin\s+admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c783031 \(TRUNCATED\)\s+Nonreplayable hash\s+netntlmv2\s+hashcat$/
  creds_command << ' creds add user:mscash-test1 hash:M\$test1#64cd29e36a8431a2b111378564a10631 jtr:mscash;'
  creds_expected_output_regex << /mscash-test1\s+M\$test1\#64cd29e36a8431a2b111378564a10631\s+Nonreplayable hash\s+mscash\s+test1$/
  creds_command << ' creds add user:mscash2-hashcat hash:\$DCC2\$10240#tom#e4e938d12fe5974dc42a90120bd9c90f jtr:mscash2;'
  creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_windows;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(9)
  info '[9/24] Running sql hashes in hashcat wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05;'
  creds_expected_output_regex << /mssql05_toto\s+0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908\s+Nonreplayable hash\s+mssql05\s+toto$/
  creds_command << ' creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql;'
  creds_expected_output_regex << /mssql_foo\s+0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6 \(TRUNCATED\)\s+Nonreplayable hash\s+mssql\s+FOO$/
  creds_command << ' creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12;'
  creds_expected_output_regex << /mssql12_Password1!\s+0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE \(TRUNCATED\)\s+Nonreplayable hash\s+mssql12\s+Password1!$/
  creds_command << ' creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql;'
  creds_expected_output_regex << /mysql_probe\s+445ff82636a7ba59\s+Nonreplayable hash\s+mysql\s+probe$/
  creds_command << ' creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1;'
  creds_expected_output_regex << /mysql-sha1_tere\s+\*5AD8F88516BD021DD43F171E2C785C69F8E54ADB\s+Nonreplayable hash\s+mysql-sha1\s+tere$/
  # hashcat des,oracle is a no go: https://github.com/rapid7/metasploit-framework/blob/7a7b009161d6b0839653f21296864da3365402a0/lib/metasploit/framework/password_crackers/cracker.rb#L152-L155
  # creds_command << ' creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle;'
  # creds_expected_output_regex << /simon\s+4F8BC1809CB2AF77\s+Nonreplayable hash\s+des,oracle\s+A$/
  # creds_command << ' creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle;'
  # creds_expected_output_regex << /SYSTEM\s+9EEDFA0AD26C6D52\s+Nonreplayable hash\s+des,oracle\s+THALES$/
  # can't escape ;?
  # creds_command << ' creds add user:DEMO hash:\'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C\' jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle11_epsilon hash:"S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A\\\\;H:DC9894A01797D91D92ECA1DA66242209\\\\;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C" jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle12c_epsilon hash:"H:DC9894A01797D91D92ECA1DA66242209\\\\;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B" jtr:pbkdf2,oracle12c;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860;'
  # creds_expected_output_regex << /example\s+md5be86a79bf2043622d58d5453c47d4860\s+Postgres md5\s+raw-md5,postgres\s+password$/

  creds_command << ' use auxiliary/analyze/crack_databases;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(10)
  info '[10/24] Running mobile hashes in hashcat wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:samsungsha1 hash:D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1 jtr:android-samsung-sha1;'
  creds_expected_output_regex << /samsungsha1\s+D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1\s+Nonreplayable hash\s+android-samsung-sha1\s+1234$/
  creds_command << ' creds add user:androidsha1 hash:9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5 jtr:android-sha1;'
  creds_expected_output_regex << /androidsha1\s+9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5\s+Nonreplayable hash\s+android-sha1\s+1234$/
  creds_command << ' creds add user:androidmd5 hash:1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5 jtr:android-md5;'
  creds_expected_output_regex << /androidmd5\s+1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5\s+Nonreplayable hash\s+android-md5\s+1234$/
  creds_command << ' use auxiliary/analyze/crack_mobile;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(11)
  info '[11/24] Running osx hashes in hashcat wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:xsha_hashcat hash:1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683 jtr:xsha;'
  creds_expected_output_regex << /xsha_hashcat\s+1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683\s+Nonreplayable hash\s+xsha\s+hashcat$/
  creds_command << ' creds add user:pbkdf2_hashcat hash:\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222 jtr:PBKDF2-HMAC-SHA512;'
  creds_expected_output_regex << /pbkdf2_hashcat\s+\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$7 \(TRUNCATED\)\s+Nonreplayable hash\s+PBKDF2-HMAC-SHA512\s+hashcat$/
  creds_command << ' creds add user:xsha512_hashcat hash:648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d jtr:xsha512;'
  creds_expected_output_regex << /xsha512_hashcat\s+648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c0 \(TRUNCATED\)\s+Nonreplayable hash\s+xsha512\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_osx;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

if options[:test] == 'all' || options[:test].include?(12)
  info '[12/24] Running webapp hashes in hashcat wordlist mode...'
  tempfile = Tempfile.new('john_pot')
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST true; setg verbose true;'
  creds_command << ' creds add user:mediawiki_hashcat hash:\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898 jtr:mediawiki;'
  creds_expected_output_regex << /mediawiki_hashcat\s+\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898\s+Nonreplayable hash\s+mediawiki\s+hashcat$/
  creds_command << ' creds add user:phpass_p_hashcat hash:\$P\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_p_hashcat\s+\$P\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:phpass_h_hashcat hash:\$H\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_h_hashcat\s+\$H\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:atlassian_hashcat hash:{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa jtr:PBKDF2-HMAC-SHA1;'
  creds_expected_output_regex << %r{atlassian_hashcat\s+\{PKCS5S2\}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa\s+Nonreplayable\s+hash\s+PBKDF2-HMAC-SHA1\s+hashcat$}
  creds_command << ' use auxiliary/analyze/crack_webapps;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{tempfile.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    tempfile.close!
    tempfile.unlink
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    exit 1
  end
  tempfile.close!
  tempfile.unlink
end

wordlist.close!
wordlist.unlink

pot_file = Tempfile.new('john_pot')
File.open(pot_file, 'w') { |file| file.write("$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/:password\nrEK1ecacw.7.c:password\n_J9..K0AyUubDrfOgO4s:password\n$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe:password\n$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5:password\n$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1:password\n$LM$4a3b108f3fa6cb6d:D\n$LM$e52cac67419a9a22:PASSWOR\n$NT$8846f7eaee8fb117ad06bdd830b7586c:password\nM$test1#64cd29e36a8431a2b111378564a10631:test1\n$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f:hashcat\n$NETNTLM$cb8086049ec4736c338d08f8e26de933$9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:hashcat\n$NETNTLMv2$ADMINN46iSNekpT$08ca45b7d7ea58ee$88dcbe4446168966a153a0064958dac6$5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030:hashcat\n0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254:FOO\n0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908:toto\n0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16:Password1!\n445ff82636a7ba59:probe\n*5AD8F88516BD021DD43F171E2C785C69F8E54ADB:tere\nO$SIMON#4f8bc1809cb2af77:A\nO$SYSTEM#9eedfa0ad26c6d52:THALES\n9860a48ca459d054f3fef0f8518cf6872923dae2:81fcb23bcadd6c5:1234\nd1b19a90b87fc10c304e657f37162445dae27d16:a006983800cc3dd1:1234\n1c0a0fdb673fba36beaeb078322c7393:81fcb23bcadd6c5:1234\n1430823483D07626EF8BE3FDA2FF056D0DFD818DBFE47683:hashcat\n$LION$648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d:hashcat\n$pbkdf2-hmac-sha512$35460.93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05.752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222:hashcat\n$pbkdf2-hmac-sha1$10000$37323237333437363735323036323731$d0c38acef03f149b4b37c5a8319feeefcbd34912127ba96f3dfa5c22f49bbc1a:hashcat\n$H$984478476IagS59wHZvyQMArzfx58u.:hashcat\n$P$984478476IagS59wHZvyQMArzfx58u.:hashcat\n$B$56668501$0ce106caa70af57fd525aeaf80ef2898:hashcat\ne52cac67419a9a22:PASSWOR\n4a3b108f3fa6cb6d:D\n8846f7eaee8fb117ad06bdd830b7586c:password\n64cd29e36a8431a2b111378564a10631:test1:test1\nu4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c:hashcat\nADMIN::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030:hashcat\n5ad8f88516bd021dd43f171e2c785c69f8e54adb:tere\n648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d:hashcat\n$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222:hashcat\n{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa:hashcat\n") }
info "john.pot file created at: #{pot_file.path}"

if options[:test] == 'all' || options[:test].include?(13)
  info '[13/24] Running *nix hashes in john pot mode...'
  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:des_password hash:rEK1ecacw.7.c jtr:des;'
  creds_expected_output_regex << /des_password\s+rEK1ecacw\.7\.c\s+Nonreplayable hash\s+des\s+password$/
  creds_command << ' creds add user:md5_password hash:\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5;'
  creds_expected_output_regex << %r{md5_password\s+\$1\$O3JMY\.Tw\$AdLnLjQ/5jXF9\.MTp3gHv/\s+Nonreplayable hash\s+md5\s+password$}
  creds_command << ' creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi;'
  creds_expected_output_regex << /bsdi_password\s+_J9\.\.K0AyUubDrfOgO4s\s+Nonreplayable hash\s+bsdi\s+password$/
  creds_command << ' creds add user:sha256_password hash:\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt;'
  creds_command << ' set SHA256 true;'
  creds_expected_output_regex << %r{sha256_password\s+\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP\.Os80yXhTurpBMUbA5\s+Nonreplayable hash\s+sha256,crypt\s+password$}
  creds_command << ' creds add user:sha512_password hash:\$6\$zWwwXKNj\$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt;'
  creds_command << ' set SHA512 true;'
  creds_expected_output_regex << %r{sha512_password\s+\$6\$zWwwXKNj\$gLAOoZCjcr8p/\.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcV \(TRUNCATED\)\s+Nonreplayable hash\s+sha512,crypt\s+password$}
  creds_command << ' creds add user:blowfish_password hash:\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf;'
  creds_command << ' set BLOWFISH true;'
  creds_expected_output_regex << %r{blowfish_password\s+\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe\s+Nonreplayable hash\s+bf\s+password$}
  creds_command << ' use auxiliary/analyze/crack_linux;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(14)
  info '[14/24] Running windows hashes in john pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm;'
  creds_expected_output_regex << /lm_password\s+e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt;'
  creds_expected_output_regex << /nt_password\s+aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:u4-netntlm hash:u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c jtr:netntlm;'
  creds_expected_output_regex << /u4-netntlm\s+u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a \(TRUNCATED\)\s+Nonreplayable hash\s+netntlm\s+hashcat$/
  creds_command << ' creds add user:admin hash:admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 jtr:netntlmv2;'
  creds_expected_output_regex << /admin\s+admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c783031 \(TRUNCATED\)\s+Nonreplayable hash\s+netntlmv2\s+hashcat$/
  creds_command << ' creds add user:mscash-test1 hash:M\$test1#64cd29e36a8431a2b111378564a10631 jtr:mscash;'
  creds_expected_output_regex << /mscash-test1\s+M\$test1\#64cd29e36a8431a2b111378564a10631\s+Nonreplayable hash\s+mscash\s+test1$/
  creds_command << ' creds add user:mscash2-hashcat hash:\$DCC2\$10240#tom#e4e938d12fe5974dc42a90120bd9c90f jtr:mscash2;'
  creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_windows;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(15)
  info '[15/24] Running sql hashes in john pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05;'
  creds_expected_output_regex << /mssql05_toto\s+0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908\s+Nonreplayable hash\s+mssql05\s+toto$/
  creds_command << ' creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql;'
  creds_expected_output_regex << /mssql_foo\s+0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6 \(TRUNCATED\)\s+Nonreplayable hash\s+mssql\s+FOO$/
  creds_command << ' creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12;'
  creds_expected_output_regex << /mssql12_Password1!\s+0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE \(TRUNCATED\)\s+Nonreplayable hash\s+mssql12\s+Password1!$/
  creds_command << ' creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql;'
  creds_expected_output_regex << /mysql_probe\s+445ff82636a7ba59\s+Nonreplayable hash\s+mysql\s+probe$/
  creds_command << ' creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1;'
  creds_expected_output_regex << /mysql-sha1_tere\s+\*5AD8F88516BD021DD43F171E2C785C69F8E54ADB\s+Nonreplayable hash\s+mysql-sha1\s+tere$/
  creds_command << ' creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle;'
  creds_expected_output_regex << /simon\s+4F8BC1809CB2AF77\s+Nonreplayable hash\s+des,oracle\s+A$/
  creds_command << ' creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle;'
  creds_expected_output_regex << /SYSTEM\s+9EEDFA0AD26C6D52\s+Nonreplayable hash\s+des,oracle\s+THALES$/
  # can't escape ;?
  # creds_command << ' creds add user:DEMO hash:\'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C\' jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle11_epsilon hash:"S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A\\\\;H:DC9894A01797D91D92ECA1DA66242209\\\\;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C" jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle12c_epsilon hash:"H:DC9894A01797D91D92ECA1DA66242209\\\\;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B" jtr:pbkdf2,oracle12c;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860;'
  # creds_expected_output_regex << /example\s+md5be86a79bf2043622d58d5453c47d4860\s+Postgres md5\s+raw-md5,postgres\s+password$/

  creds_command << ' use auxiliary/analyze/crack_databases;'
  creds_command << " set CUSTOM_WORDLIST #{wordlist.path};"
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(16)
  info '[16/24] Running osx hashes in john pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:xsha_hashcat hash:1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683 jtr:xsha;'
  creds_expected_output_regex << /xsha_hashcat\s+1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683\s+Nonreplayable hash\s+xsha\s+hashcat$/
  creds_command << ' creds add user:pbkdf2_hashcat hash:\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222 jtr:PBKDF2-HMAC-SHA512;'
  creds_expected_output_regex << /pbkdf2_hashcat\s+\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$7 \(TRUNCATED\)\s+Nonreplayable hash\s+PBKDF2-HMAC-SHA512\s+hashcat$/
  creds_command << ' creds add user:xsha512_hashcat hash:648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d jtr:xsha512;'
  creds_expected_output_regex << /xsha512_hashcat\s+648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c0 \(TRUNCATED\)\s+Nonreplayable hash\s+xsha512\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_osx;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(17)
  info '[17/24] Running webapp hashes in john pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:mediawiki_hashcat hash:\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898 jtr:mediawiki;'
  creds_expected_output_regex << /mediawiki_hashcat\s+\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898\s+Nonreplayable hash\s+mediawiki\s+hashcat$/
  creds_command << ' creds add user:phpass_p_hashcat hash:\$P\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_p_hashcat\s+\$P\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:phpass_h_hashcat hash:\$H\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_h_hashcat\s+\$H\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:atlassian_hashcat hash:{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa jtr:PBKDF2-HMAC-SHA1;'
  creds_expected_output_regex << %r{atlassian_hashcat\s+\{PKCS5S2\}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa\s+Nonreplayable\s+hash\s+PBKDF2-HMAC-SHA1\s+hashcat$}
  creds_command << ' use auxiliary/analyze/crack_webapps;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(18)
  info '[18/24] Running *nix hashes in hashcat pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:des_password hash:rEK1ecacw.7.c jtr:des;'
  creds_expected_output_regex << /des_password\s+rEK1ecacw\.7\.c\s+Nonreplayable hash\s+des\s+password$/
  creds_command << ' creds add user:md5_password hash:\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5;'
  creds_expected_output_regex << %r{md5_password\s+\$1\$O3JMY\.Tw\$AdLnLjQ/5jXF9\.MTp3gHv/\s+Nonreplayable hash\s+md5\s+password$}
  creds_command << ' creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi;'
  creds_expected_output_regex << /bsdi_password\s+_J9\.\.K0AyUubDrfOgO4s\s+Nonreplayable hash\s+bsdi\s+password$/
  creds_command << ' creds add user:sha256_password hash:\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt;'
  creds_command << ' set SHA256 true;'
  creds_expected_output_regex << %r{sha256_password\s+\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP\.Os80yXhTurpBMUbA5\s+Nonreplayable hash\s+sha256,crypt\s+password$}
  creds_command << ' creds add user:sha512_password hash:\$6\$zWwwXKNj\$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt;'
  creds_command << ' set SHA512 true;'
  creds_expected_output_regex << %r{sha512_password\s+\$6\$zWwwXKNj\$gLAOoZCjcr8p/\.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcV \(TRUNCATED\)\s+Nonreplayable hash\s+sha512,crypt\s+password$}
  creds_command << ' creds add user:blowfish_password hash:\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf;'
  creds_command << ' set BLOWFISH true;'
  creds_expected_output_regex << %r{blowfish_password\s+\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe\s+Nonreplayable hash\s+bf\s+password$}
  creds_command << ' use auxiliary/analyze/crack_linux;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(19)
  info '[19/24] Running windows hashes in hashcat pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm;'
  creds_expected_output_regex << /lm_password\s+e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+PASSWORD$/
  creds_command << ' creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt;'
  creds_expected_output_regex << /nt_password\s+aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:u4-netntlm hash:u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c jtr:netntlm;'
  creds_expected_output_regex << /u4-netntlm\s+u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a \(TRUNCATED\)\s+Nonreplayable hash\s+netntlm\s+hashcat$/
  creds_command << ' creds add user:admin hash:admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 jtr:netntlmv2;'
  creds_expected_output_regex << /admin\s+admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c783031 \(TRUNCATED\)\s+Nonreplayable hash\s+netntlmv2\s+hashcat$/
  creds_command << ' creds add user:mscash-test1 hash:M\$test1#64cd29e36a8431a2b111378564a10631 jtr:mscash;'
  creds_expected_output_regex << /mscash-test1\s+M\$test1\#64cd29e36a8431a2b111378564a10631\s+Nonreplayable hash\s+mscash\s+test1$/
  creds_command << ' creds add user:mscash2-hashcat hash:\$DCC2\$10240#tom#e4e938d12fe5974dc42a90120bd9c90f jtr:mscash2;'
  creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_windows;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(20)
  info '[20/24] Running sql hashes in hashcat pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05;'
  creds_expected_output_regex << /mssql05_toto\s+0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908\s+Nonreplayable hash\s+mssql05\s+toto$/
  creds_command << ' creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql;'
  creds_expected_output_regex << /mssql_foo\s+0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6 \(TRUNCATED\)\s+Nonreplayable hash\s+mssql\s+FOO$/
  creds_command << ' creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12;'
  creds_expected_output_regex << /mssql12_Password1!\s+0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE \(TRUNCATED\)\s+Nonreplayable hash\s+mssql12\s+Password1!$/
  creds_command << ' creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql;'
  creds_expected_output_regex << /mysql_probe\s+445ff82636a7ba59\s+Nonreplayable hash\s+mysql\s+probe$/
  creds_command << ' creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1;'
  creds_expected_output_regex << /mysql-sha1_tere\s+\*5AD8F88516BD021DD43F171E2C785C69F8E54ADB\s+Nonreplayable hash\s+mysql-sha1\s+tere$/
  # hashcat des,oracle is a no go: https://github.com/rapid7/metasploit-framework/blob/7a7b009161d6b0839653f21296864da3365402a0/lib/metasploit/framework/password_crackers/cracker.rb#L152-L155
  # creds_command << ' creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle;'
  # creds_expected_output_regex << /simon\s+4F8BC1809CB2AF77\s+Nonreplayable hash\s+des,oracle\s+A$/
  # creds_command << ' creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle;'
  # creds_expected_output_regex << /SYSTEM\s+9EEDFA0AD26C6D52\s+Nonreplayable hash\s+des,oracle\s+THALES$/
  # can't escape ;?
  # creds_command << ' creds add user:DEMO hash:\'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C\' jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle11_epsilon hash:"S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A\\\\;H:DC9894A01797D91D92ECA1DA66242209\\\\;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C" jtr:raw-sha1,oracle;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:oracle12c_epsilon hash:"H:DC9894A01797D91D92ECA1DA66242209\\\\;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B" jtr:pbkdf2,oracle12c;'
  # creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  # creds_command << ' creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860;'
  # creds_expected_output_regex << /example\s+md5be86a79bf2043622d58d5453c47d4860\s+Postgres md5\s+raw-md5,postgres\s+password$/

  creds_command << ' use auxiliary/analyze/crack_databases;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(21)
  info '[21/24] Running mobile hashes in hashcat pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:samsungsha1 hash:D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1 jtr:android-samsung-sha1;'
  creds_expected_output_regex << /samsungsha1\s+D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1\s+Nonreplayable hash\s+android-samsung-sha1\s+1234$/
  creds_command << ' creds add user:androidsha1 hash:9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5 jtr:android-sha1;'
  creds_expected_output_regex << /androidsha1\s+9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5\s+Nonreplayable hash\s+android-sha1\s+1234$/
  creds_command << ' creds add user:androidmd5 hash:1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5 jtr:android-md5;'
  creds_expected_output_regex << /androidmd5\s+1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5\s+Nonreplayable hash\s+android-md5\s+1234$/
  creds_command << ' use auxiliary/analyze/crack_mobile;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(22)
  info '[22/24] Running osx hashes in hashcat pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:xsha_hashcat hash:1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683 jtr:xsha;'
  creds_expected_output_regex << /xsha_hashcat\s+1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683\s+Nonreplayable hash\s+xsha\s+hashcat$/
  creds_command << ' creds add user:pbkdf2_hashcat hash:\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222 jtr:PBKDF2-HMAC-SHA512;'
  creds_expected_output_regex << /pbkdf2_hashcat\s+\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$7 \(TRUNCATED\)\s+Nonreplayable hash\s+PBKDF2-HMAC-SHA512\s+hashcat$/
  creds_command << ' creds add user:xsha512_hashcat hash:648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d jtr:xsha512;'
  creds_expected_output_regex << /xsha512_hashcat\s+648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c0 \(TRUNCATED\)\s+Nonreplayable hash\s+xsha512\s+hashcat$/
  creds_command << ' use auxiliary/analyze/crack_osx;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(23)
  info '[23/24] Running webapp hashes in hashcat pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg INCREMENTAL false;setg USE_CREDS false; setg USE_DB_INFO false; setg USE_DEFAULT_WORDLIST false; setg USE_HOSTNAMES false; setg USE_ROOT_WORDS false; setg WORDLIST false; setg verbose true;'
  creds_command << ' creds add user:mediawiki_hashcat hash:\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898 jtr:mediawiki;'
  creds_expected_output_regex << /mediawiki_hashcat\s+\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898\s+Nonreplayable hash\s+mediawiki\s+hashcat$/
  creds_command << ' creds add user:phpass_p_hashcat hash:\$P\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_p_hashcat\s+\$P\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:phpass_h_hashcat hash:\$H\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_h_hashcat\s+\$H\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:atlassian_hashcat hash:{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa jtr:PBKDF2-HMAC-SHA1;'
  creds_expected_output_regex << %r{atlassian_hashcat\s+\{PKCS5S2\}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa\s+Nonreplayable\s+hash\s+PBKDF2-HMAC-SHA1\s+hashcat$}
  creds_command << ' use auxiliary/analyze/crack_webapps;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' set action hashcat;'
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

if options[:test] == 'all' || options[:test].include?(24)
  info '[24/24] Running all hashes in john apply_pot mode...'

  creds_expected_output_regex = []
  creds_command = 'setg verbose true;'
  creds_command << ' creds add user:des_password hash:rEK1ecacw.7.c jtr:des;'
  creds_expected_output_regex << /des_password\s+rEK1ecacw\.7\.c\s+Nonreplayable hash\s+des\s+password$/
  creds_command << ' creds add user:md5_password hash:\$1\$O3JMY.Tw\$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5;'
  creds_expected_output_regex << %r{md5_password\s+\$1\$O3JMY\.Tw\$AdLnLjQ/5jXF9\.MTp3gHv/\s+Nonreplayable hash\s+md5\s+password$}
  creds_command << ' creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi;'
  creds_expected_output_regex << /bsdi_password\s+_J9\.\.K0AyUubDrfOgO4s\s+Nonreplayable hash\s+bsdi\s+password$/
  creds_command << ' creds add user:sha256_password hash:\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt;'
  creds_expected_output_regex << %r{sha256_password\s+\$5\$MnfsQ4iN\$ZMTppKN16y/tIsUYs/obHlhdP\.Os80yXhTurpBMUbA5\s+Nonreplayable hash\s+sha256,crypt\s+password$}
  creds_command << ' creds add user:sha512_password hash:\$6\$zWwwXKNj\$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt;'
  creds_expected_output_regex << %r{sha512_password\s+\$6\$zWwwXKNj\$gLAOoZCjcr8p/\.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcV \(TRUNCATED\)\s+Nonreplayable hash\s+sha512,crypt\s+password$}
  creds_command << ' creds add user:blowfish_password hash:\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf;'
  creds_expected_output_regex << %r{blowfish_password\s+\$2a\$05\$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe\s+Nonreplayable hash\s+bf\s+password$}
  creds_command << ' creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm;'
  creds_expected_output_regex << /lm_password\s+e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt;'
  creds_expected_output_regex << /nt_password\s+aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\s+NTLM hash\s+nt,lm\s+password$/
  creds_command << ' creds add user:u4-netntlm hash:u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c jtr:netntlm;'
  creds_expected_output_regex << /u4-netntlm\s+u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a \(TRUNCATED\)\s+Nonreplayable hash\s+netntlm\s+hashcat$/
  creds_command << ' creds add user:admin hash:admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 jtr:netntlmv2;'
  creds_expected_output_regex << /admin\s+admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c783031 \(TRUNCATED\)\s+Nonreplayable hash\s+netntlmv2\s+hashcat$/
  creds_command << ' creds add user:mscash-test1 hash:M\$test1#64cd29e36a8431a2b111378564a10631 jtr:mscash;'
  creds_expected_output_regex << /mscash-test1\s+M\$test1\#64cd29e36a8431a2b111378564a10631\s+Nonreplayable hash\s+mscash\s+test1$/
  creds_command << ' creds add user:mscash2-hashcat hash:\$DCC2\$10240#tom#e4e938d12fe5974dc42a90120bd9c90f jtr:mscash2;'
  creds_expected_output_regex << /mscash2-hashcat\s+\$DCC2\$10240\#tom\#e4e938d12fe5974dc42a90120bd9c90f\s+Nonreplayable hash\s+mscash2\s+hashcat$/
  creds_command << ' creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05;'
  creds_expected_output_regex << /mssql05_toto\s+0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908\s+Nonreplayable hash\s+mssql05\s+toto$/
  creds_command << ' creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql;'
  creds_expected_output_regex << /mssql_foo\s+0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6 \(TRUNCATED\)\s+Nonreplayable hash\s+mssql\s+FOO$/
  creds_command << ' creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12;'
  creds_expected_output_regex << /mssql12_Password1!\s+0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE \(TRUNCATED\)\s+Nonreplayable hash\s+mssql12\s+Password1!$/
  creds_command << ' creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql;'
  creds_expected_output_regex << /mysql_probe\s+445ff82636a7ba59\s+Nonreplayable hash\s+mysql\s+probe$/
  creds_command << ' creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1;'
  creds_expected_output_regex << /mysql-sha1_tere\s+\*5AD8F88516BD021DD43F171E2C785C69F8E54ADB\s+Nonreplayable hash\s+mysql-sha1\s+tere$/
  creds_command << ' creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle;'
  creds_expected_output_regex << /simon\s+4F8BC1809CB2AF77\s+Nonreplayable hash\s+des,oracle\s+A$/
  creds_command << ' creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle;'
  creds_expected_output_regex << /SYSTEM\s+9EEDFA0AD26C6D52\s+Nonreplayable hash\s+des,oracle\s+THALES$/
  # mobile is done on hashcat, not john, so skip these
  # creds_command << ' creds add user:samsungsha1 hash:D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1 jtr:android-samsung-sha1;'
  # creds_expected_output_regex << /samsungsha1\s+D1B19A90B87FC10C304E657F37162445DAE27D16:a006983800cc3dd1\s+Nonreplayable hash\s+android-samsung-sha1\s+1234$/
  # creds_command << ' creds add user:androidsha1 hash:9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5 jtr:android-sha1;'
  # creds_expected_output_regex << /androidsha1\s+9860A48CA459D054F3FEF0F8518CF6872923DAE2:81fcb23bcadd6c5\s+Nonreplayable hash\s+android-sha1\s+1234$/
  # creds_command << ' creds add user:androidmd5 hash:1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5 jtr:android-md5;'
  # creds_expected_output_regex << /androidmd5\s+1C0A0FDB673FBA36BEAEB078322C7393:81fcb23bcadd6c5\s+Nonreplayable hash\s+android-md5\s+1234$/
  creds_command << ' creds add user:xsha_hashcat hash:1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683 jtr:xsha;'
  creds_expected_output_regex << /xsha_hashcat\s+1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683\s+Nonreplayable hash\s+xsha\s+hashcat$/
  creds_command << ' creds add user:pbkdf2_hashcat hash:\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222 jtr:PBKDF2-HMAC-SHA512;'
  creds_expected_output_regex << /pbkdf2_hashcat\s+\$ml\$35460\$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05\$7 \(TRUNCATED\)\s+Nonreplayable hash\s+PBKDF2-HMAC-SHA512\s+hashcat$/
  creds_command << ' creds add user:xsha512_hashcat hash:648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d jtr:xsha512;'
  creds_expected_output_regex << /xsha512_hashcat\s+648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c0 \(TRUNCATED\)\s+Nonreplayable hash\s+xsha512\s+hashcat$/
  creds_command << ' creds add user:mediawiki_hashcat hash:\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898 jtr:mediawiki;'
  creds_expected_output_regex << /mediawiki_hashcat\s+\$B\$56668501\$0ce106caa70af57fd525aeaf80ef2898\s+Nonreplayable hash\s+mediawiki\s+hashcat$/
  creds_command << ' creds add user:phpass_p_hashcat hash:\$P\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_p_hashcat\s+\$P\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:phpass_h_hashcat hash:\$H\$984478476IagS59wHZvyQMArzfx58u. jtr:phpass;'
  creds_expected_output_regex << /phpass_h_hashcat\s+\$H\$984478476IagS59wHZvyQMArzfx58u\.\s+Nonreplayable hash\s+phpass\s+hashcat$/
  creds_command << ' creds add user:atlassian_hashcat hash:{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa jtr:PBKDF2-HMAC-SHA1;'
  creds_expected_output_regex << %r{atlassian_hashcat\s+\{PKCS5S2\}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa\s+Nonreplayable\s+hash\s+PBKDF2-HMAC-SHA1\s+hashcat$}
  creds_command << ' use auxiliary/analyze/apply_pot;'
  creds_command << " set POT #{pot_file.path};"
  creds_command << ' run; creds -d; exit;'
  info "Run Command: #{creds_command}" if options[:verbose]
  unless run_msfconsole(creds_command, creds_expected_output_regex)
    puts '-------------------------------'
    error "Credential verification failed. Exiting."
    pot_file.close!
    pot_file.unlink
    exit 1
  end
end

pot_file.close!
pot_file.unlink

puts '-------------------------------'
good 'All checks passed successfully!'
info "Script runtime: #{Time.now - start_time} seconds"