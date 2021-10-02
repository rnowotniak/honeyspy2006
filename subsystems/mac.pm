#!/usr/bin/perl -w

use strict;
use Log::Log4perl;

package subsystems::mac;

Log::Log4perl::init($ENV{'LOG4PERLCONF'});
my $logger = Log::Log4perl->get_logger('mac');


sub init {
	my ($self) = @_;

	$logger->debug("Initializing MAC spoofing subsystem");

	$self->{'spoofed_mac'} = {};
}

sub checkAbility {
	my ($self) = @_;

	my ($ebtables, $arptables, $ifconfig);
	foreach (split(/:/, $ENV{'PATH'})) {
		$ebtables = 1 if -x "$_/ebtables";
		$arptables = 1 if -x "$_/arptables";
		$ifconfig = 1 if -x "$_/ifconfig";
		last if $ebtables && $arptables && $ifconfig;
	}
	$self->{'abilities'}{'mac'} = 1 if $ebtables && $arptables && $ifconfig;
}

sub _updateArpTables {
	my ($self) = @_;

	system('ebtables -t nat -F PREROUTING;'
	. 'arptables -t nat -F POSTROUTING;'
	. 'arptables -t mangle -F OUTPUT;') >> 8 == 0
		or return "Couldn't clean ebtables and arptables rules";

	while ((my ($ip, $mac) = each(%{$self->{'spoofed_mac'}}))) {

		next unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		next unless $mac =~ /([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}/;

		system("arptables -t mangle -A OUTPUT --h-length 6 -o honey "
		. "-s $ip -j mangle --mangle-mac-s $mac") >> 8 == 0
			or return "Couldn't set arptables rule ($ip -> $mac)";

		system("ebtables -t nat -A PREROUTING -d $mac -j redirect") >> 8 == 0
			or return "Couldn't set ebtables rule (to redirect $mac)";

		system("ebtables -t nat -A POSTROUTING -p ipv4 --ip-src $ip "
		. "-j snat --to-source $mac") >> 8 == 0
			or return "Couldn't set ebtables rule ($mac POSTROUTING entry)";
	}

	return 0;
}

sub setMAC {
	my ($self, $addr, $mac) = @_;
	$logger->info("Setting $mac address on $addr");

	$self->{'spoofed_mac'}{$addr} = $mac;
	$self->_updateArpTables();
}

sub delMAC {
	my ($self, $addr) = @_;
	$logger->info("Disabling MAC mangling on $addr");

	delete $self->{'spoofed_mac'}{$addr};
	return $self->_updateArpTables();
}

sub getMAC {
	my ($self, $ip) = @_;

	my %macs = %{$self->{'spoofed_mac'}};

	return $self->{'spoofed_mac'}{$ip} if defined $ip;
	return %macs;
}

# usuwa wszystkie odwzorowania adres -> mac
sub cleanMAC {
	my ($self) = @_;
	
	$self->{'spoofed_mac'} = {};
	return $self->_updateArpTables();
}


1;

