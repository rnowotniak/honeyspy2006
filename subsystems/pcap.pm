#!/usr/bin/perl -w

use strict;
use Log::Log4perl;
use Net::Pcap;

package subsystems::pcap;

Log::Log4perl::init($ENV{'LOG4PERLCONF'});
my $logger = Log::Log4perl->get_logger('pcap');


sub init {
	my ($self) = @_;

	$logger->debug("Initializing pcap subsystem");

	$self->{'pcap'} = undef,
	$self->{'pcap_filters'} = [],
	$self->{'compiled_filter'} = undef,

}

sub checkAbility {
	my ($self) = @_;

	$self->{'abilities'}{'pcap'} = 0;

	my $err;
	Net::Pcap::open_live('any', 512, 1, 0, \$err);
	$self->{'abilities'}{'pcap'} = 1 if (! $err);
}

sub _compileFilter {
	my ($self) = @_;
	my $compiled;

	return unless @{$self->{'pcap_filters'}} && $self->{'pcap'};

	# sprawdzic kazda regule po kolei
	foreach (@{$self->{'pcap_filters'}}) {
		my $err = Net::Pcap::compile($self->{'pcap'}, \$compiled, $_, 1, 0);
		if ($err) {
			$err = "Error in rule: $_";
			$logger->error($err);
			return $err;
		}
	}

	if (@{$self->{'pcap_filters'}} > 1) {
		# zrobic alternatywe logiczna wszystkich regul
		my @filters = @{$self->{'pcap_filters'}};
		my $sum = $filters[0];
		$sum = "($sum) or ($_)" foreach @filters[1..$#filters];
		my $err = '';
		$err = Net::Pcap::compile($self->{'pcap'}, \$compiled, $sum, 1, 0);
		if ($err) {
			$err = "Error in rules sum: $sum. " . Net::Pcap::geterr($self->{'pcap'});
			$logger->error($err);
			return $err;
		}
	}

	Net::Pcap::setfilter($self->{'pcap'}, $compiled);

	return 0;
}

sub _setupPcap {
	my ($self) = @_;
	my $err;
	
	$self->{'pcap'} =
		Net::Pcap::open_live('any', 512, 1, 0, \$err);
	$logger->error($err) if $err;

	$logger->debug("pcap datalink: " . Net::Pcap::datalink($self->{'pcap'}));

	$self->_compileFilter();
}

sub _pcapPacket {
	my ($user_data, $hdr, $pkt) = @_;

	my $eth_obj = NetPacket::Ethernet->decode($pkt);
	my $msg = "Packet matched PCAP rule.";
	$msg .= " src mac: " . $eth_obj->{'src_mac'};
	$msg .= " dst mac: " . $eth_obj->{'dst_mac'}
		if defined($eth_obj->{'dst_mac'});

	#my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
	my $ip_obj = NetPacket::IP->decode(substr($eth_obj->{'data'}, 2));
	$msg .= " | ";
	$msg .= 'src:' . $ip_obj->{'src_ip'};
	$msg .= ' dst:' . $ip_obj->{'dest_ip'};
	$msg .= ' ipver:' . $ip_obj->{'ver'};
	$msg .= ' tos:' . $ip_obj->{'tos'};
	$msg .= ' len:' . $ip_obj->{'len'};
	$msg .= ' id:' . $ip_obj->{'id'};
	$msg .= ' proto:' . getprotobynumber($ip_obj->{'proto'});
	$msg .= ' flags:' . $ip_obj->{'flags'};

	if ($ip_obj->{'proto'} == getprotobyname('tcp')) {
		my $tcp_obj = NetPacket::TCP->decode($ip_obj->{'data'});
		$msg .= ' | tcp';
		$msg .= ' src port: ' . $tcp_obj->{'src_port'};
		$msg .= ' dst port: ' . $tcp_obj->{'dest_port'};
	}

	$logger->info($msg);
}


########################################
# Nasluchiwanie ruchu sieciowego (PCAP)
#
sub addFilter {
	my ($self, $new_filter) = @_;
	$logger->debug("Adding filter: $new_filter");

	push @{$self->{'pcap_filters'}}, $new_filter;
	$self->_compileFilter();
}

sub replaceFilters {
	my ($self, $new_filter) = @_;
	
	$self->{'pcap_filters'} = [$new_filter];
	$self->_compileFilter();
}

sub delFilter {
	my ($self, $number) = @_;

	if ($number) {
		my @filters = @{$self->{'pcap_filters'}};
		@filters = @filters[0..$number-1, $number+1..$#filters];
		$self->{'pcap_filters'} = \@filters;
	}
	else {
		$self->{'pcap_filters'} = [];
	}

	return 0;
}

sub getFilters {
	my ($self) = @_;
	return @{$self->{'pcap_filters'}};
}

sub getFilter {
	my ($self, $number) = @_;
	return @{$self->{'pcap_filters'}} unless defined $number;
	return $self->{'pcap_filters'}[$number];
}

sub disablePcap {
	my ($self) = @_;
	return unless $self->{'pcap'};

	my $fd = Net::Pcap::fileno($self->{'pcap'});
	$self->_removefh($fd);

	Net::Pcap::close($self->{'pcap'});
	$self->{'pcap'} = undef;

	return 0;
}

sub enablePcap {
	my ($self) = @_;

	if (!$self->{'abilities'}{'pcap'}) {
		my $err = "Pcap not supported";
		$logger->error($err);
		return $err;
	}

	if ($self->{'pcap'}) {
		my $err = "Pcap already enabled";
		$logger->info($err);
		return $err;
	}

	$self->_setupPcap();

	my $fd = Net::Pcap::fileno($self->{'pcap'});
	$self->_addfh($fd, 'r');
	$self->{'r_handlers'}{$fd} = sub {
		$logger->debug("Got packet");
		Net::Pcap::loop($self->{'pcap'}, 1, \&_pcapPacket, 'aaa');
	};

	return 0;
}

1;

