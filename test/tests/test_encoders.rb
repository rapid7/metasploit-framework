#
# Simple script to test a group of encoders against every exploit in the framework.
# Focuses on exploits' badchars to check if a payload can be encoded.
# Ignores target architecture/platform, only cares about real-world badchars.
#

# Resolve the base path of the file, handling symlinks
msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

# Add Metasploit's lib directory to Ruby's load path
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

# Load Metasploit environment
require 'msfenv'

# Create a simple framework instance
$msf = Msf::Simple::Framework.create

# Get the list of exploits
EXPLOITS = $msf.exploits

# Helper function to print messages
def print_line(message)
  $stdout.puts(message)
end

# Format badchars as hex string (\xNN)
def format_badchars(badchars)
  str = ''
  if (badchars)
    badchars.each_byte do |b|
      str << "\\x%02X" % [ b ]
    end
  end
  str
end

# Test one encoder against all exploits using a payload
def encoder_v_payload(encoder_name, payload, verbose = false)
  success = 0
  fail = 0
  # Iterate through all exploits
  EXPLOITS.each_module do |name, mod|
    exploit = mod.new
    print_line("\n#{encoder_name} v #{name} (#{format_badchars(exploit.payload_badchars)})") if verbose
    begin
      # Create encoder and try to encode payload respecting badchars
      encoder = $msf.encoders.create(encoder_name)
      raw = encoder.encode(payload, exploit.payload_badchars, nil, nil)
      success += 1
    rescue
      # If encoding fails, log and continue
      print_line("    FAILED! badchars=#{format_badchars(exploit.payload_badchars)}\n") if verbose
      fail += 1
    end
  end
  return [ success, fail ]
end

# Generate a payload with default options
def generate_payload(name)
  payload = $msf.payloads.create(name)

  # Options for reverse_tcp payload
  payload.datastore['LHOST'] = '192.168.2.1'
  payload.datastore['RHOST'] = '192.168.2.254'
  payload.datastore['RPORT'] = '5432'
  payload.datastore['LPORT'] = '4444'
  # Options for exec payload
  payload.datastore['CMD'] = 'calc'
  # Generic options
  payload.datastore['EXITFUNC'] = 'thread'

  return payload.generate
end

# Run tests for a list of encoders against a payload
def run(encoders, payload_name, verbose = false)
  payload = generate_payload(payload_name)

  # Create a results table
  table = Rex::Text::Table.new(
    'Header' => 'Encoder v Payload Test - ' + ::Time.new.strftime("%d-%b-%Y %H:%M:%S"),
    'Indent' => 4,
    'Columns' => [ 'Encoder Name', 'Success', 'Fail' ]
  )

  # Test each encoder and add results to table
  encoders.each do |encoder_name|
    success, fail = encoder_v_payload(encoder_name, payload, verbose)
    table << [ encoder_name, success, fail ]
  end

  return table
end

# Script entry point
if ($0 == __FILE__)

  print_line("[+] Starting.\n")

  # List of encoders to test
  encoders = [
    'x86/bloxor',
    'x86/shikata_ga_nai',
    'x86/jmp_call_additive',
    'x86/fnstenv_mov',
    'x86/countdown',
    'x86/call4_dword_xor'
  ]

  # Payload to use in tests
  payload_name = 'windows/shell/reverse_tcp'

  # Verbose mode disabled by default
  verbose = false

  # Run tests and generate results table
  result_table = run(encoders, payload_name, verbose)

  # Print results
  print_line("\n\n#{result_table.to_s}\n\n")

  print_line("[+] Finished.\n")
end
