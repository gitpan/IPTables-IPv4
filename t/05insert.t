#!/usr/bin/perl

use IPTables::IPv4;

BEGIN { $| = 1; print "1..28\n"; }
$testiter = 1;

my $table = IPTables::IPv4::init('filter');
unless ($table) {
	print "not ok 1\n";
	exit(1);
}
print "ok ", $testiter++, "\n";

foreach my $chain (qw/foo REJECT MASQUERADE REDIRECT/) {
	$table->create_chain($chain) || print "not ";
	print "ok ", $testiter++, "\n";
}

$table->insert_entry("foo", {jump => "RETURN"}, 0) || print "not ";
print "ok ", $testiter++, "\n";

my @rules = $table->list_rules("foo");
unless (scalar(@rules) == 1) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[0]})) == 3 && $rules[0]->{jump} eq "RETURN") {
	print "not ";
}
print "ok ", $testiter++, "\n";

$table->insert_entry("foo", {jump => "MASQUERADE"}, 0) || print "not ";
print "ok ", $testiter++, "\n";

@rules = $table->list_rules("foo");
unless (scalar(@rules) == 2) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[0]})) == 3 && $rules[0]->{jump} eq "MASQUERADE") {
	print "not ";
}
print "ok ", $testiter++, "\n";

$table->insert_entry("foo", {}, 3) && print "not ";
print "ok ", $testiter++, "\n";
$table->insert_entry("foo", {jump => "REDIRECT"}, 2) || print "not ";
print "ok ", $testiter++, "\n";

@rules = $table->list_rules("foo");
unless (scalar(@rules) == 3) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[2]})) == 3 && $rules[2]->{jump} eq "REDIRECT") {
	print "not ";
}
print "ok ", $testiter++, "\n";

$table->insert_entry("foo", {}, 1) || print "not ";
print "ok ", $testiter++, "\n";

@rules = $table->list_rules("foo");
unless (scalar(@rules) == 4) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[1]})) == 2) {
	print "not ";
}
print "ok ", $testiter++, "\n";

$table->delete_num_entry("foo", 4) && print "not ";
print "ok ", $testiter++, "\n";

$table->delete_num_entry("foo", 3) || print "not ";
print "ok ", $testiter++, "\n";

@rules = $table->list_rules("foo");
unless (scalar(@rules) == 3) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[2]})) == 3 && $rules[2]->{jump} ne "REDIRECT") {
	print "not ";
}
print "ok ", $testiter++, "\n";

$table->delete_num_entry("foo", 1) || print "not ";
print "ok ", $testiter++, "\n";

@rules = $table->list_rules("foo");
unless (scalar(@rules) == 2) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[0]})) == 3 && $rules[0]->{jump} ne "REJECT") {
	print "not ";
}
print "ok ", $testiter++, "\n";

$table->delete_entry("foo", {jump => "RETURN"}) || print "not ";
print "ok ", $testiter++, "\n";

@rules = $table->list_rules("foo");
unless (scalar(@rules) == 1) {
	print "not ";
}
print "ok ", $testiter++, "\n";
unless (scalar(keys(%{$rules[0]})) == 3 && $rules[0]->{jump} ne "RETURN") {
	print "not ";
}
print "ok ", $testiter++, "\n";

foreach my $chain ($table->list_chains()) {
	$table->flush_entries($chain);
}

foreach my $chain ($table->list_chains()) {
	unless ($table->builtin($chain)) {
		$table->delete_chain($chain);
	}
}

exit(0);
