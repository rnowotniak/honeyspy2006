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


package FHTrapper;

use Log::Log4perl qw(:easy);

sub TIEHANDLE {
	my $class = shift;
	bless [], $class;
}

sub PRINT {
	my ($self, @data) = @_;
	$Log::Log4perl::caller_depth++;
	$logger->info(@data);
	$Log::Log4perl::caller_depth--;
}

1;

