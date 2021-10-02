#!/usr/bin/perl -T
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

package Node;

use strict;
use IO::Select;
use Log::Log4perl (':easy');
use MasterAppender;
use Storable qw(nstore_fd freeze thaw);
use IO::Socket::SSL;
use IO::Socket::INET;
use NetPacket::Ethernet qw(:strip);
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Net::Pcap;
use POSIX qw(setsid);
use Carp;
use Socket;
use IPC::Open2;

use subsystems::p0f;
use subsystems::fingerprint;
use subsystems::mac;
use subsystems::pcap;
use subsystems::ipaliases;
use subsystems::superserver;

use Master;
use Commons;
use FHTrapper;

require Exporter;
our @SUBSYSTEMS = qw{
	subsystems::p0f
	subsystems::fingerprint
	subsystems::mac
	subsystems::pcap
	subsystems::ipaliases
	subsystems::superserver
};
our @ISA = ('Exporter', @SUBSYSTEMS);

my $logger = get_logger();

use constant CORRECT_CERT =>
	"/C=PL/O=HoneySpy network/OU=Master Server/CN=Master";



#
# Konstruktor
#
sub new {
	my ($class,  $config_file) = 
		(ref($_[0]) || $_[0], $_[1]);

	$logger->debug("Node constructor\n");

	my $self = {
		'name' => 'unnamed',
		'master_sock' => undef,
		'mode' => 'sensor',
		'appender' => undef,

		# Atrybuty dzialania serwera
		'abilities' => {},

		# nienazwany potok do slania logow z podprocesow do node'a (in, out)
		'log_pipe' => undef,

		# Handlery dla zdarzen na uchwytach plikow
		'r_handlers' => {},
		'w_handlers' => {},
		'e_handlers' => {},

		# Zbiory uchwytow plikow, ktore trzeba obserwowac
		'r_set' => new IO::Select(),
		'w_set' => new IO::Select(),
		'e_set' => new IO::Select(),

      'stimeout' => 3,
      'reconnect' => 4, # tyle sekund miedzy reconnect
      'connected' => 0
	};

	bless $self, $class;

	$self->readConfig($config_file)
		if defined $config_file;

	$self->_checkAbilities();

	#
	# Inicjalizacja kazdego z podsystemow
	#
	foreach my $subsystem (@SUBSYSTEMS) {
		my $meth = $subsystem.'::init';
		$self->$meth;
	}

	return $self;
}


################################################################################
# Metody prywatne
################################################################################

sub _checkAbilities {
	my ($self) = @_;
	$logger->debug("Checking my abilities...");
	
	foreach my $subsystem (@SUBSYSTEMS) {
		my $meth = $subsystem.'::checkAbility';
		$self->$meth;
	}

	my @abilities = grep {$self->{'abilities'}{$_}} keys %{$self->{'abilities'}};
	local $" = ',';
	no warnings;
	$logger->debug("My abilities are: @abilities");
}

sub _searchForRegexInCmd {
	my ($self, $regex, $cmd) = @_;
	foreach (qx/$cmd/) {
		return 1 if (/$regex/);
	}
	return 0;
}


#
# Jesli funkcja wywolana przez te funkcje zwrocila
# cokolwiek defined, to _callFunction odesle to jako odpowiedz
# do mastera.
# Jesli funkcja wywolana zwrocila undef, to znaczy,
# zeby nie odsylac, bo moze funkcja sama ustawi(la) w_handler
#
sub _callFunction {
	my ($self, $function, $arrayctx, @args) = @_;
	my @result;
	my $local = 1;

	eval {
		no strict 'refs';
		if ($arrayctx) {
			@result = @{[ $self->$function(@args) ]};
		}
		else {
			@result = (scalar $self->$function(@args));
		}
	};
	for ($@) {
		last unless ($@);

		if (/Can't locate object method/) {
			$result[0] = "No such function ($function) on remote side";
			last;
		}
		else {
			$result[0] = "Error $_ during excecution of remote called function";
		}

		$logger->error($result[0]);
	}

	my $undef_returned = scalar @result == 1 && !defined($result[0]);
	if (! $undef_returned) {
		my $master_sock = $self->{'master_sock'};
		$self->{'w_handlers'}{$master_sock} = sub {
			Commons::sendDataToSocket($master_sock, ['ret', @result]);
			$self->_removefh($master_sock, 'w');
		};
		$self->_addfh($master_sock, 'w');
	}

	return 0;
}

sub _configure_master_connection {
   my ($self, $master) = @_;
	
	$self->_addfh($master, 're');
	$self->{'r_handlers'}{$master} = sub {
		$self->process_command($master);
	};

	$self->{'connected'} = 1;
	$self->{'master_sock'} = $master;

	my $appender = Log::Log4perl::Appender->new(
		'MasterAppender',
		name => 'MasterAppender',
		socket => $self->{'master_sock'}
	);

	my $layout = Log::Log4perl::Layout::PatternLayout->new("%m%n");
	$appender->layout($layout);
	$logger->add_appender($appender);
	$self->{'appender'} = $appender;
}


sub _connect_to_master {
   my ($self) = @_;
	my $master;

	$logger->debug("Connecting to $self->{'master_addr'}:$self->{'master_port'}...");
	$master = IO::Socket::SSL->new(
		PeerAddr => $self->{'master_addr'},
		PeerPort => $self->{'master_port'},
		Proto    => 'tcp',
		SSL_use_cert => 1,

		SSL_key_file => $self->{'ssl_key'},
		SSL_cert_file => $self->{'ssl_cert'},

		SSL_ca_file => $self->{'ca_file'},

		SSL_verify_mode => 0x01);
	if (!$master) {
		$logger->fatal("unable to create socket: ", IO::Socket::SSL->errstr, "\n");
		return 0;
	}
	my ($subject_name, $issuer_name, $cipher, $trusted_master);
	$trusted_master = 0;
	if(ref($master) eq "IO::Socket::SSL") {
		$subject_name = $master->peer_certificate("subject");
		$issuer_name = $master->peer_certificate("issuer");
		$cipher = $master->get_cipher();

		$logger->debug("Certificate's subject: $subject_name");
		$logger->debug("Certificate's issuer: $issuer_name");

		if ($subject_name eq CORRECT_CERT
			&& $issuer_name eq CORRECT_CERT) {
				$trusted_master = 1;
		}
	}
	if (!$trusted_master) {
		$logger->fatal("Master doesn't have correct certificate!");
		exit(1);
	}
	$logger->info("Certificate recognized.");
	$logger->debug("Using cipher: $cipher");

	$self->_configure_master_connection($master);
}

sub _setLogPipe {
	my ($self) = @_;
	pipe PIPEIN, PIPEOUT;
	PIPEIN->autoflush(1);
	PIPEOUT->autoflush(1);
	$self->{'log_pipe'} = [*PIPEIN, *PIPEOUT];
	$self->{'r_handlers'}{*PIPEIN} = sub {
		my $msg = <PIPEIN>;
		chomp $msg;
		$logger->info($msg);
	};
	$self->_addfh(*PIPEIN, 'r');
}

sub _removefh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->remove($fh);
		delete $self->{$_.'_handlers'}{$fh};
	}
}

sub _addfh {
	my ($self, $fh, $setname) = @_;
	$setname = 'rwe' unless defined $setname;

	foreach (split(//,$setname)) {
		confess "No such set: $_" unless /r|w|e/;
		$self->{$_.'_set'}->add($fh);
	}
}


################################################################################
# Metody publiczne
################################################################################


#
# Wczytanie konfiguracji z pliku
#
sub readConfig {
	my ($self, $file) = @_;
	return "No config file given." unless $file;

	my $config = do $file;

	return "Couldn't parse config file ($!, $@)."
		unless defined $config;

	my @config_params = qw {
		name
		master_addr
		master_port
		listen_addr
		listen_port
		ca_file
		ssl_key
		ssl_cert
	};

	foreach (@config_params) {
		$self->{$_} = $config->{$_}
			if defined $config->{$_};
	}

	return 0;
}


#
# U¿ywane g³ównie do testów RPC
#
sub getAbilities {
	my ($self) = @_;
	return %{$self->{'abilities'}};
}

sub getName() {
	my ($self) = @_;
	return $self->{'name'};
}


#
# Pobranie listy sensorów podleg³ych temu wêz³owi
# (czyli ³±cznie z nim samym)
#
sub getSensors() {
	my ($self) = @_;
	my @names = $self->{'name'};
	my %sensors = ();

	foreach (keys %{$self->{'sensors'}}) {
		if (! exists($sensors{$self->{'sensors'}{$_}})) {
			push @names, $self->{'sensors'}{$_}{'name'};
			$sensors{$self->{'sensors'}{$_}} = 1;
		}
	}

	return @names;
}

sub info {
	my $msg = "I'm ${\($_[0]->{name})} node";
	$logger->debug($msg);
	return $msg;
}

sub kill {
	$logger->info('Node is going down in a moment');
	$SIG{'ALRM'} = sub {
		exit 0;
	};
	alarm 1;
	return 0;
}

#
# Destruktor
#
sub DESTROY {
#	$logger->debug("Node ${\($_[0]->{'name'})} destructor\n");
}


######################################################
# G³ówna pêtla serwera (obs³uga zdarzeñ na gniazdach)
#

sub run {
	my $self = shift;
	$logger->info("Starting node " . $self->{'name'});

	local $| = 1;
	$SIG{'PIPE'} = sub {
		$logger->warn('Broken pipe');
	};
	$SIG{'CHLD'} = sub {
		wait();
		$self->{'processes_spawned'}--
			if $self->{'processes_spawned'} > 0;
		my $msg = "Subprocess finished ";
		$msg .= "(running: ".$self->{'processes_spawned'}."/".$self->{'processes_limit'}.").";
		$logger->info($msg);
	};

	$self->_setLogPipe();

	if ($self->{'mode'} eq 'sensor') {
		if (! $self->{'connected'}) {
			$logger->debug("Trying to (re)connect to my master");
			$self->_connect_to_master();
		}
	}

	$logger->debug("Entering main loop - node " . $self->{'name'});
	for (;;) {
		$logger->debug("Waiting on select(2) syscall...");

		$logger->debug("Write watched handles: " , $self->{'w_set'}->handles);
		my ($r_ready, $w_ready, $e_ready) =
			IO::Select->select(
				$self->{'r_set'}, $self->{'w_set'}, $self->{'e_set'},
				$self->{'stimeout'});

		if (!defined($r_ready)) {
			#
			# Na zadnym uchwycie nie bylo zdarzenia
			#
			$logger->debug("Timeout");
			if ($self->{'mode'} eq 'sensor') {
				if (! $self->{'connected'}) {
					$logger->debug("Trying to (re)connect to my master");
					$self->_connect_to_master();
				}
			}
			next;
		}

		foreach my $fh (@$r_ready) {
			$logger->debug("Something ($fh) in read ready set");

			$self->{'r_handlers'}{$fh}()
				if exists($self->{'r_handlers'}{$fh});
		}
		foreach my $fh (@$w_ready) {
			$logger->debug("Something ($fh) in write ready set");

			$self->{'w_handlers'}{$fh}()
				if exists($self->{'w_handlers'}{$fh});
		}
	}
}


#
# Wykonuje funkcjê przes³an± przez sieæ wraz z argumentami
# i jej kontekstem wywo³ania
#
sub process_command {
	my ($self, $sock) = @_;

	my $peek = $sock->peek(undef, 1);
	if (!defined $peek) {
		$logger->error("peek() : $!");
		return;
	}
	if ($peek == 0) {
		Log::Log4perl->eradicate_appender('MasterAppender');
		$self->{'appender'} = undef;
		$logger->debug("My master closed connection.");
		$self->_removefh($sock, 're');
		$self->{'connected'} = 0;
		close($sock);
	}
	else {
		$logger->debug("Processing data from server.");

		my $buf;
		sysread($sock, $buf, 4);
		my $len = unpack('N', $buf);
		sysread($sock, $buf, $len);
		my ($function, $arrayctx, @args);
		eval {
			($function, $arrayctx, @args) = @{thaw($buf)};
		};
		for ($@) {
			if (/Magic number checking on storable string failed/) {
				$logger->error("Wrong data received from client.");
				return;
			}
		}

		local $" = ',';
		$logger->debug("Running $function(@args) in "
			. ($arrayctx?'list':'scalar') . ' context');

		# XXX
		$self->_callFunction($function, $arrayctx, @args);
		return 0;
	}
}


#
# Wykonuje funkcjê na podanym wê¼le sieci
#
sub runOnNode {
	my ($self, $name, $function, @args) = @_;
	my @result;

	if ($name eq $self->{'name'}) {
		no strict 'refs';
		$self->_callFunction($function, wantarray, @args);
		return undef;
	}

	return "No such node: $name"
		unless exists($self->{'sensors'}{$name});

	#
	# Odbedzie sie wywolanie zdalne
	#

	my $sensor = $self->{'sensors'}{$name};
	my $sensor_sock = $sensor->{'socket'};

	$self->{'w_handlers'}{$sensor_sock} = sub {
		$sensor->doOnReturn(sub {
				my ($self, @ret) = @_;
				my $node = $self->{'master'};
				$self->doOnReturn(undef);
				$logger->info(@ret);
				$node->{'w_handlers'}{$node->{'master_sock'}} = sub {
					Commons::sendDataToSocket(
						$node->{'master_sock'}, ['ret', @ret]);
					$node->_removefh($node->{'master_sock'}, 'w');
				};
				$node->_addfh($node->{'master_sock'}, 'w');
			});
		$sensor->call($function, wantarray, @args);
	};
	$self->_addfh($sensor->{'socket'}, 'w');

	return undef;
}


1;

# vim: set ts=3 sw=3 ft=perl:

