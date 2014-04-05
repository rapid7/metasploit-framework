#
# Simple script to test a group of encoders against every exploit in the framework, 
# specifically for the exploits badchars, to see if a payload can be encoded. We ignore
# the target arch/platform of the exploit as we just want to pull out real world bad chars.
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

require 'fastlib'
require 'msfenv'
require 'msf/base'

$msf = Msf::Simple::Framework.create

EXPLOITS = $msf.exploits

def print_line( message )
  $stdout.puts( message )
end

def format_badchars( badchars )
  str = ''
  if( badchars )
    badchars.each_byte do | b |
      str << "\\x%02X" % [ b ]
    end
  end
  str
end

def encoder_v_payload( encoder_name, payload, verbose=false )
  success = 0
  fail    = 0
  EXPLOITS.each_module do | name, mod |
  
    exploit = mod.new
    print_line( "\n#{encoder_name} v #{name} (#{ format_badchars( exploit.payload_badchars ) })" ) if verbose
    begin
      encoder = $msf.encoders.create( encoder_name )
      raw = encoder.encode( payload, exploit.payload_badchars, nil, nil )
      success += 1
    rescue
      print_line( "    FAILED! badchars=#{ format_badchars( exploit.payload_badchars ) }\n" ) if verbose
      fail += 1
    end
  end
  return [ success, fail ]
end

def generate_payload( name )

  payload = $msf.payloads.create( name )
  
  # set options for a reverse_tcp payload
  payload.datastore['LHOST']    = '192.168.2.1'
  payload.datastore['RHOST']    = '192.168.2.254'
  payload.datastore['RPORT']    = '5432'
  payload.datastore['LPORT']    = '4444'
  # set options for an exec payload
  payload.datastore['CMD']      = 'calc'
  # set generic options
  payload.datastore['EXITFUNC'] = 'thread'

  return payload.generate
end

def run( encoders, payload_name, verbose=false )

  payload = generate_payload( payload_name )

  table = Rex::Ui::Text::Table.new(
    'Header'  => 'Encoder v Payload Test - ' + ::Time.new.strftime( "%d-%b-%Y %H:%M:%S" ),
    'Indent'  => 4,
    'Columns' => [ 'Encoder Name', 'Success', 'Fail' ]
  )

  encoders.each do | encoder_name |

    success, fail = encoder_v_payload( encoder_name, payload, verbose )

    table << [ encoder_name, success, fail ]
    
  end

  return table	
end

if( $0 == __FILE__ )

  print_line( "[+] Starting.\n" )

  encoders = [ 
    'x86/bloxor', 
    'x86/shikata_ga_nai', 
    'x86/jmp_call_additive', 
    'x86/fnstenv_mov', 
    'x86/countdown', 
    'x86/call4_dword_xor'
  ]

  payload_name = 'windows/shell/reverse_tcp'
  
  verbose = false
  
  result_table = run( encoders, payload_name, verbose )

  print_line( "\n\n#{result_table.to_s}\n\n" )

  print_line( "[+] Finished.\n" )
end



  