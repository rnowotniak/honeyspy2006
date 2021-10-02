#!/usr/bin/perl -w

use strict;
use Log::Log4perl;

package subsystems::ipaliases;

Log::Log4perl::init($ENV{'LOG4PERLCONF'});
my $logger = Log::Log4perl->get_logger('ipaliases');


sub init {
	my ($self) = @_;

	$logger->debug("Initializing IP aliases subsystem");
	
	$self->{'ip_aliases'} = {};

	$self->_initIPAliases()
		if $self->{'abilities'}{'ipaliases'};

}

sub checkAbility {
	my ($self) = @_;

	$self->{'abilities'}{'ipaliases'} = $> ? 0 : 1;
}

sub _initIPAliases {
	my ($self) = @_;
	
	my $ifname;
	foreach (qx/ifconfig -a/) {
		if (/^(honey:\d+)/) {
			$ifname = $1;
		}
		elsif ($ifname && /inet addr:(\S+)\s/) {
			$self->{'ip_aliases'}{$1} = $ifname;
			undef $ifname;
		}
	}
}

sub addIPAlias {
	my ($self, $ip) = @_;
	return unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;

	my $ifname = 'honey:' . scalar keys %{$self->{'ip_aliases'}};
	$self->{'ip_aliases'}{$ip} = $ifname;

	system ("ifconfig $ifname $ip") >> 8 == 0
		or return "Couldn't assign $ip to $ifname";

	return 0;
}

sub delIPAlias {
	my ($self, $ip) = @_;
	return unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;

	if (!exists $self->{'ip_aliases'}{$ip}) {
		my $msg = "$ip was not assigned by honeypot";
		$logger->warn($msg);
		return $msg;
	}

	my $ifname = $self->{'ip_aliases'}{$ip};
	$logger->info("Removing interface $ifname");

	system("ifconfig $ifname down") >> 8 == 0
		or return "Couldn't disable $ifname interface";

	delete $self->{'ip_aliases'}{$ip};

	return 0;
}

sub getIPAlias {
	my ($self, $ip) = @_;

	my %aliases = %{$self->{'ip_aliases'}};

	return %aliases unless defined $ip;
	return $self->{'ip_aliases'}{$ip};
}

1;

