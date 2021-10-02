#!/usr/bin/perl
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


package Sensor;

use Log::Log4perl (':easy');
use Log::Log4perl::Level;

use Storable qw(freeze thaw);
use Node;
use Commons;

require Exporter;
@ISA = qw(Exporter);

my $logger = get_logger();

#
# Sensor powinien miec atrybuty
# 	nazwa
# 	uchwyt gniazda (gniazda do sensora! nie mastera)
# 	referencja do obiekty klasy Master
#

sub new {
	$logger->debug("konstruktor\n");

	my $class = ref($_[0]) || $_[0];
	my $self = {
		'name' => undef,
		'socket' => undef,
		'master' => undef,

		# wywolywane przez sensor, gdy podlegly wezel zwrocil rezultat wykonanego rozkazu
		'return_handler' => undef,
	};


	if (ref($_[1]) eq 'HASH')  {
		foreach my $attr qw(name socket master) {
			$self->{$attr} = $_[1]->{$attr}
				if defined $_[1]->{$attr};
		}
	}
	else {
		$self->{'name'} = $_[1];
	}

	return bless $self, $class;
}


sub _recvFromPeer {
	my ($self) = @_;
	my $sock = $self->{'socket'};
	my $buf;

	sysread($sock, $buf, 4);
	my $len = unpack('N', $buf);
	sysread($sock, $buf, $len);
	my @resp;
	eval {
		@resp = @{thaw($buf)};
	};
	for ($@) {
		if (/Magic number checking on storable string failed/) {
			$logger->error("Wrong data received from sensor.");
			return;
		}
	}
	local $" = "\n   -> ";
	$logger->debug("Received data from Sensor:\n   -> @resp\n");
	return @resp;
}



#
#
# sub info() {
# 	$logger->debug("--- Jestem sensor ${\($_[0]->{name})}\n");
# }
# 
# sub getName() {
# 	return shift->{'name'};
# }
#

#
# Czyta komunikat od sensora (sa dane)
#
sub read {
	my ($self, $what) = @_;
	my ($sock) = $self->{'socket'};
	$logger->debug("Reading data from sensor");

	do {
		my $peek = $sock->peek(undef, 1);
		if (!defined $peek) {
			$logger->error("peek(): $!");
			return -2;
		}
		if ($peek == 0) {
			$logger->info("Sensor closed connection");
			$self->{'master'}->remove_sensor($self);
			return -1;
		}

		my ($type, @data) = $self->_recvFromPeer();
		if ($type eq 'ret') {
			$self->{'return_handler'}($self, @data);
			return @data;
		}
		elsif ($type eq 'log') {
			my %data = @data;
			$logger->log(
				Log::Log4perl::Level::to_priority($data{'log4p_level'}),
				"[$self->{'name'}] $data{'message'}");
		}
		else {
			$logger->fatal("It shouldn't happen. Broken protocol! :(");
			return -2;
		}
	} while ($what && $what eq 'return_code');
}

#
# ustawia funkcje, ktora bedzie wykonana w momencie,
# gdy ten sensor zwrocil rezultat wyslanego mu rozkazu
#
sub doOnReturn {
	my ($self, $handler) = @_;
	$self->{'return_handler'} = $handler;
}


sub AUTOLOAD {
	my ($self) = @_;
	$logger->debug("I should try to run $AUTOLOAD via RPC:\n");

	my $function = $AUTOLOAD;
	$function =~ s/.*:://;
	shift;
	$self->call($function, wantarray, @_);
}


#
# Wywo³uje zdalnie na tym sensorze podan± funkcjê
#
sub call {
	my ($self, $name, $arrayctx, @args) = @_;
	my $sensor = $self->{'name'};
	local $" = ',';
	$logger->debug("I'm running function $name(@args) on $sensor sensor in "
		. ($arrayctx ? 'list' : 'scalar') . " context\n");

	$self->sendToPeer($name, $arrayctx, @args);
	$self->{'master'}->_removefh($self->{'socket'}, 'w')
		if defined $self->{'master'};

	return 0;
}

sub DESTROY {
	$logger->debug("Destruktor Sensora ${\($_[0]->{'name'})}\n");
}


sub sendToPeer {
	my ($self) = shift;
	my $sock = $self->{'socket'};

	return Commons::sendDataToSocket($sock, [@_]);
}


1;

