#!/usr/bin/perl

use IPTables::IPv4;

BEGIN { $| = 1; print "1..10\n"; }
$testiter = 1;

my $table = IPTables::IPv4::init('filter');
unless ($table) {
	print "not ok 1\n";
	exit(1);
}
print "ok ", $testiter++, "\n";

$table->create_chain("foo") || print "not ";
print "ok ", $testiter++, "\n";
$table->replace_entry("foo", {}, 0) && print "not ";
print "ok ", $testiter++, "\n";
$table->append_entry("foo", {}) || print "not ";
print "ok ", $testiter++, "\n";
$table->append_entry("foo", {}) || print "not ";
print "ok ", $testiter++, "\n";
$table->replace_entry("foo", {jump => "DROP"}, 0) || print "not ";
print "ok ", $testiter++, "\n";
$table->replace_entry("foo", {jump => "ACCEPT"}, 1) || print "not ";
print "ok ", $testiter++, "\n";

my @rules = $table->list_rules("foo");
print "not " unless scalar(@rules) == 2; 
print "ok ", $testiter++, "\n";

foreach my $target (qw/DROP ACCEPT/) {
	my $rule = shift(@rules);
	print "not " unless scalar(keys(%$rule)) == 3 && $$rule{jump} eq $target;
}

$table->flush_entries("foo") || print "not ";
print "ok ", $testiter++, "\n";
$table->delete_chain("foo") || print "not ";
print "ok ", $testiter++, "\n";

exit(0);
