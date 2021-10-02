#!/usr/bin/perl -w
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use strict;

################################################################################
# USTAW TU PRAWIDLOWE, DLA TWOJEGO SYSTEMU, SCIEZKI
################################################################################

use constant DIR => '/home/rob/HoneySpy-svn/webapp/';
use constant CERTDIR => '/home/rob/HoneySpy-svn/certs/';
use lib DIR . '../';

################################################################################



BEGIN {
	if (!$ENV{'LOG4PERLCONF'}) {
		$ENV{'LOG4PERLCONF'} = DIR . '/../log4perl.conf';
	}
}


use Template;
use Template::Constants qw(:debug);
use IO::Socket::SSL;
use CGI;
use Sensor;
use Node;
use Cwd;

my $cgi = new CGI;
my $tt = Template->new({INCLUDE_PATH => DIR,
# DEBUG => DEBUG_ALL
});

$| = 1;


our $sensor;


print $cgi->header(-charset=>'iso-8859-2');

if (! $cgi->param('server') || ! $cgi->param('pass')) {
	$tt->process('templates/login.html')
		or die $tt->error();
}
else {
	if (checkLogin($cgi->param('server'), $cgi->param('pass')) < 0) {
		print "Couldn't connect to network with used credentials ";
	}
	else {

		my @val;
		my $val_r = \@val;
		my ($name, %abilities, %ipaliases, %macs, @filters, %services);

		$sensor->doOnReturn(sub {
			my ($self, @res) = @_;
			@$val_r = @res;
		});

		$sensor->getName();
		$sensor->read('return_code');
		$name = $val[0];

		[$sensor->getAbilities()];
		$sensor->read('return_code');
		%abilities = @val;

		[$sensor->getIPAlias()];
		$sensor->read('return_code');
		%ipaliases = @val;

		[$sensor->getMAC()];
		$sensor->read('return_code');
		%macs = @val;

		[$sensor->getFilter()];
		$sensor->read('return_code');
		@filters = @val;

		[$sensor->getService()];
		$sensor->read('return_code');
		%services = @val;

		my @abilities = ();
		foreach (keys(%abilities)) {
			if ($abilities{$_}) {
				push @abilities, $_;
			}
		}

		my @ipaliases = keys (%ipaliases);

		my $vars = {
			'name' => $name,
			'abilities' => \@abilities,
			'ipaliases' => \@ipaliases,
			'macs' => \%macs,
			'filters' => \@filters,
			'services' => \%services,
			'server' => $cgi->param('server'),
			'password' => $cgi->param('pass'),
			'result' => '',
			'command' => $cgi->param('command'),
		};

		if (0) {
			print STDERR $name;
			print STDERR "\n";
			print STDERR %abilities;
			print STDERR "\n";
			print STDERR %ipaliases;
			print STDERR "\n";
			print STDERR %macs;
			print STDERR "\n";
			print STDERR @filters;
			print STDERR "\n";
			print STDERR %services;
			print STDERR "\n";
		}

		my ($command, @args) = split(/\s+/, $cgi->param('command'));
		if ($command) {
			print STDERR "-> $command";

			[$sensor->$command(@args)];
			$sensor->read('return_code');
			$vars->{'result'} = join("\n<br/>", @val);
		}

		$tt->process('templates/main.html', $vars);
	}
}


sub checkLogin {
	my ($server, $pass) = @_;

	my $socket = IO::Socket::SSL->new(PeerAddr => $server,
		PeerPort => 9000,
		Proto    => 'tcp',
		SSL_use_cert => 1,

		SSL_key_file => CERTDIR . '/admin-key.enc',
		SSL_cert_file => CERTDIR . '/admin-cert.pem',
		SSL_ca_file => CERTDIR . '/master-cert.pem',

		SSL_passwd_cb => sub { return $pass; },

		SSL_verify_mode => 0x01
	);
	$sensor = new Sensor({
		name => 'main',
		socket => $socket,
	});
	if ($socket) {
#		close $socket;
		return 0;
	}
	print STDERR IO::Socket::SSL->errstr;
	return -1;
}

