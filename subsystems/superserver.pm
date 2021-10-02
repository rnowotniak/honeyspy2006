#!/usr/bin/perl -w

use strict;
use Log::Log4perl;
use POSIX qw(setsid);

package subsystems::superserver;

Log::Log4perl::init($ENV{'LOG4PERLCONF'});
my $logger = Log::Log4perl->get_logger('superserver');


sub init {
	my ($self) = @_;

	$logger->debug("Initializing superserver subsystem");

	$self->{'ports'} = {};  # dzialajace uslugi
							 	 	# "addr/proto/port" ->
									#	 {socket -> ..., script -> ..., args -> ...}
	$self->{'processes_spawned'} = 0;
	$self->{'processes_limit'} = 10;
	
}

sub checkAbility {
	my ($self) = @_;

	# nie zrob nic
	return undef;
}

#####################################
# Przypisanie us³ugi na danym porcie
#
sub addService {
	my ($self, $addr, $proto, $port, $script, @args) = @_;
	$logger->info("Adding service on $addr:$port ($proto)");

	my $socket = new IO::Socket::INET(
		LocalAddr => $addr,
		LocalPort => $port,
		Proto => $proto,
		Listen => 5,
		Reuse => 1
	);
	if (!$socket) {
		my $msg = "Couldn't open socket: $!";
		$logger->error($msg);
		return $msg;
	}

	$self->{'ports'}{"$addr/$proto/$port"}{'socket'} = $socket;
	$self->{'ports'}{"$addr/$proto/$port"}{'script'} = $script;
	$self->{'ports'}{"$addr/$proto/$port"}{'args'} = join(' ', @args);

	$self->_addfh($socket, 'r');
	$self->{'r_handlers'}{$socket} = sub {
		my $client = $socket->accept();
		if (! $client) {
			$logger->error("Couldn't accept connection ($!)");
			return 1;
		}
		if ($self->{'processes_spawned'} >= $self->{'processes_limit'}) {
			$logger->error("Maximum processes already running. Dropping connection from " . $client->peerhost);
			close $client;
			return 1;
		}

		my $pid = fork();
		if (! $pid) {
			POSIX::setsid();
			POSIX::close(3);
			close $self->{'log_pipe'}[0];
			POSIX::dup(fileno($self->{'log_pipe'}[1]));
			open(STDIN, "<&=".fileno($client));
			open(STDOUT, ">&=".fileno($client));
			{ exec($script, @args); }
			$logger->error("Couldn't run script ($!)");
			exit 1;
		}
		$logger->info("Connection to service $script from " . $client->peerhost .
			"[pid: ".$pid."]");
		$self->{'processes_spawned'}++;
	};

	return 0;
}

sub delService {
	my ($self, $addr, $proto, $port) = @_;
	if (! exists $self->{'ports'}{"$addr/$proto/$port"}) {
		my $msg = "No service is bound there";
		$logger->warn($msg);
		return $msg;
	}

	$logger->info("Removing service from $addr:$port ($proto)");
	my $fh = $self->{'ports'}{"$addr/$proto/$port"}{'socket'};
	$self->_removefh($fh);
	$fh->close();
	delete $self->{'ports'}{"$addr/$proto/$port"};
	return 0;
}

sub getService {
	my ($self, $addr, $proto, $port) = @_;

	if (defined $port) {
		if (defined $self->{'ports'}{"$addr/$proto/$port"}) {
			my $result;
			$result = $self->{'ports'}{"$addr/$proto/$port"}{'script'};
			$result .= ' ' . $self->{'ports'}{"$addr/$proto/$port"}{'args'}
				if defined ($self->{'ports'}{"$addr/$proto/$port"}{'args'});
			return $result;
		}
		return 0;
	}

	my %result;
	foreach (keys %{$self->{'ports'}}) {
		my $value;
		$value = $self->{'ports'}{$_}{'script'};
		$value .= ' ' . $self->{'ports'}{$_}{'args'}
			if defined ($self->{'ports'}{$_}{'args'});
		$result{$_} = $value;
	}
	return %result;
}

#
# Ustawia ile maksymalnie moze dzialaæ jednocze¶nie 
# modulow z imitacjami uslug
#
sub setServicesLimit {
	my ($self, $limit) = @_;
	return unless defined $limit;

	$self->{'processes_limit'} = $limit;
}

sub getServicesLimit {
	my ($self) = @_;
	return $self->{'processes_limit'};
}


1;

