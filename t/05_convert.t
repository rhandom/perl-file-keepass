#!/usr/bin/perl

=head1 NAME

01_kdbx.t - Check version 2 functionality of File::KeePass

=cut

use strict;
use warnings;
use Test::More tests => 17;

if (!eval {
    require MIME::Base64;
}) {
    diag "Failed to load library: $@";
  SKIP: { skip "Missing necessary libraries.\n", 70 };
    exit;
}

use_ok('File::KeePass');

my $pass = "foo";
my $ok;

my $obj1_1 = File::KeePass->new;
my $obj1_2 = File::KeePass->new;
my $obj2_1 = File::KeePass->new;
my $obj2_2 = File::KeePass->new;
my $G1 = $obj1_1->add_group({ title => 'personal' });
my $G2 = $obj1_1->add_group({ title => 'career',  group => $G1 });
my $G3 = $obj1_1->add_group({ title => 'finance', group => $G1 });
my $G4 = $obj1_1->add_group({ title => 'banking', group => $G2 });
my $G5 = $obj1_1->add_group({ title => 'credit',  group => $G2 });
my $G6 = $obj1_1->add_group({ title => 'health',  group => $G1 });
my $G7 = $obj1_1->add_group({ title => 'web',     group => $G1 });
my $G8 = $obj1_1->add_group({ title => 'hosting', group => $G7 });
my $G9 = $obj1_1->add_group({ title => 'mail',    group => $G7 });
my $G0 = $obj1_1->add_group({ title => 'Foo'      });

$obj1_1->add_entry({title => "Hey", group => $G1});
$obj1_1->add_entry({title => "Hey2", group => $G1});

$obj1_1->add_entry({title => "Hey3", group => $G5});

my $dump1 = "\n".eval { $obj1_1->dump_groups };

print "v1 -> v1\n";
$ok = $obj1_2->parse_db($obj1_1->gen_db($pass), $pass, {auto_lock => 0});
my $dump2 = "\n".eval { $obj1_2->dump_groups };
is($dump1, $dump2, "Export v1/import v1 is fine");
is(eval{$obj1_1->header->{'version'}}, undef, 'No version set on pure gen object');
is($obj1_2->header->{'version'}, 1, 'Correct version 1 of re-import');

print "v1 new -> v2\n";
$ok = $obj2_1->parse_db($obj1_1->gen_db($pass, {version => 2}), $pass, {auto_lock => 0});
my $dump3 = "\n".eval { $obj2_1->dump_groups };
is($dump2, $dump3, "Export from v1 to v2/import v2 is fine");
is(eval{$obj1_1->header->{'version'}}, undef, 'No version set on pure gen object');
is($obj2_1->header->{'version'}, 2, 'Correct version 2 of re-import');

print "v1 -> v2\n";
$ok = $obj2_1->parse_db($obj1_2->gen_db($pass, {version => 2}), $pass, {auto_lock => 0});
my $dump4 = "\n".eval { $obj2_1->dump_groups };
is($dump3, $dump4, "Export from v1 to v2/import v2 is fine");
is($obj1_2->header->{'version'}, 2, 'V1 object changed to v2');
is($obj2_1->header->{'version'}, 2, 'Correct version 2 of re-import');

print "# v2 -> v2\n";
$ok = $obj2_2->parse_db($obj2_1->gen_db($pass), $pass, {auto_lock => 0});
my $dump5 = "\n".eval { $obj2_2->dump_groups };
is($dump4, $dump5, "Export v2/import v2 is fine");
is($obj2_1->header->{'version'}, 2, 'Correct version 2');
is($obj2_2->header->{'version'}, 2, 'Correct version 2 of re-import');

print  "# v2 -> v1\n";
$ok = eval { $obj1_1->parse_db($obj2_2->gen_db($pass, {version => 1}), $pass, {auto_lock => 0}) };
ok($ok, "Gen and parse a db") or diag "Error: $@";
my $dump6 = "\n".eval { $obj1_1->dump_groups };
is($dump5, $dump6, "Export v2/import v1 is fine");
is($obj2_2->header->{'version'}, 1, 'Correct version 1');
is($obj1_1->header->{'version'}, 1, 'Correct version 1 of re-import');

__END__
my $e  = $obj->add_entry({title => 'bam', password => 'flimflam'}); # defaults to first group
ok($e, "Entry - Added an entry");
my $eid = $e->{'id'};
ok($eid, "Entry - Added an entry");
my $e2 = $obj->add_entry({title => 'bim', username => 'BIM', group => $g2});
my $eid2 = $e2->{'id'};

my @e = $obj->find_entries({title => 'bam'});
is(scalar(@e), 1, "Entry - Found one entry");
is($e[0]->{'id'}, $eid, "Entry - Is the right one");

ok(!eval { $obj->locked_entry_password($e[0]) }, 'Entry - Can unlock unlocked password');

@e = $obj->find_entries({active => 1});
is(scalar(@e), 2, "Entry - Found right number of active entries");

my $e_2 = $obj->find_entry({title => 'bam'});
is($e_2, $e, "Entry - find_entry works");

($e_2, my $e_group) = $obj->find_entry({title => 'bam'});
is($e_2, $e, "Entry - find_entry works");
is($e_group, $g, "Entry - find_entry works");

my ($e2_2, $e2_group) = $obj->find_entry({title => 'bim'});
is($e2_2, $e2, "Entry - find_entry works");
is($e2_group, $g2, "Entry - find_entry works");

###----------------------------------------------------------------###

# turn it into the binary encrypted blob
my $db = $obj->gen_db($pass);
ok($db, "Parsing - Gened a db");

# now try parsing it and make sure it is still in ok form
$obj->auto_lock(0);

my $ok = $obj->parse_db($db, $pass);
ok($ok, "Parsing - Re-parsed groups");
ok($obj->header, "Parsing - We now have a header");

ok($g = $obj->find_group({id => $gid}), "Parsing - Found a group in parsed results");
is($g->{'title'}, 'Foo', "Parsing - Was the correct group");

$e = eval { $obj->find_entry({title => 'bam'}) };
ok($e, "Parsing - Found one entry");
is($e->{'id'}, $eid, "Parsing - Is the right one");


###----------------------------------------------------------------###

# test locking and unlocking
ok(!$obj->is_locked, "Locking - Object isn't locked");
is($e->{'password'}, 'flimflam', 'Locking - Had a good unlocked password');

$obj->lock;
ok($obj->is_locked, "Locking - Object is now locked");
is($e->{'password'}, undef, 'Locking - Password is now hidden');
is($obj->locked_entry_password($e), 'flimflam', 'Locking - Can access single password');
is($e->{'password'}, undef, 'Locking - Password is still hidden');

$obj->unlock;
ok(!$obj->is_locked, "Locking - Object isn't locked");
is($e->{'password'}, 'flimflam', 'Locking - Had a good unlocked password again');


# make sure auto_lock does come one
$obj->auto_lock(1);
$ok = $obj->parse_db($db, $pass);
ok($ok, "Locking - Re-parsed groups");
ok($obj->is_locked, "Locking - Object is auto locked");


###----------------------------------------------------------------###

# test file operations
$obj->unlock;
my $file = __FILE__.".kdbx";

ok(!eval { $obj->save_db }, "File - Missing file");
ok(!eval { $obj->save_db($file) }, "File - Missing pass");
ok($obj->save_db($file, $pass), "File - Saved DB");
ok(-e $file, "File - File now exists");
{
    local $obj->{'keep_backup'} = 1;
    ok($obj->save_db($file, $pass), "File - Saved over the top but kept backup");
}
ok($obj->save_db($file, $pass), "File - Saved over the top");
$obj->clear;
ok(!eval { $obj->groups }, "File - Cleared out object");

ok(!eval { $obj->load_db }, "File - Missing file");
ok(!eval { $obj->load_db($file) }, "File - Missing pass");
ok($obj->load_db($file, $pass), "File - Loaded from file");

ok($g = $obj->find_group({id => $gid}), "File - Found a group in parsed results");
is($g->{'title'}, 'Foo', "File - Was the correct group");
ok($g->{'expanded'}, "File - Expanded was passed along correctly");

unlink($file);
unlink("$file.bak");

###----------------------------------------------------------------###

$dump = eval { $obj->dump_groups };
diag($dump);
ok($dump, "General - Ran dump groups");

###----------------------------------------------------------------###

ok(!eval { $obj->delete_entry({}) }, "Delete - fails on delete of too many entries");
ok(scalar $obj->find_entry({title => 'bam'}), 'Delete - found entry');
$obj->delete_entry({title => 'bam'});
ok(!$obj->find_entry({title => 'bam'}), 'Delete - delete_entry worked');

ok(!eval { $obj->delete_group({}) }, "Delete - fails on delete of too many groups");
ok(scalar $obj->find_group({title => 'Bar'}), 'Delete - found group');
$obj->delete_group({title => 'Bar'});
ok(!$obj->find_group({title => 'Bar'}), 'Delete - delete_group worked');

$dump = eval { $obj->dump_groups };
diag($dump);

###----------------------------------------------------------------###

# test for correct stack unwinding during the parse_group phase
my ($G, $G2, $G3);
my $obj2 = File::KeePass->new({version => 2});
$G = $obj2->add_group({ title => 'hello' });
$G = $obj2->add_group({ title => 'world',    group => $G });
$G = $obj2->add_group({ title => 'i am sam', group => $G });
$G = $obj2->add_group({ title => 'goodbye' });
$dump = "\n".eval { $obj2->dump_groups };
$ok = $obj2->parse_db($obj2->gen_db($pass), $pass);
my $dump2 = "\n".eval { $obj2->dump_groups };
#diag($dump);
is($dump2, $dump, "Dumps should match after gen_db->parse_db") && diag($dump);
#exit;

###----------------------------------------------------------------###

# test for correct stack unwinding during the parse_group phase
$obj2 = File::KeePass->new({version => 2});
$G  = $obj2->add_group({ title => 'personal' });
$G2 = $obj2->add_group({ title => 'career',  group => $G  });
$G2 = $obj2->add_group({ title => 'finance', group => $G  });
$G3 = $obj2->add_group({ title => 'banking', group => $G2 });
$G3 = $obj2->add_group({ title => 'credit',  group => $G2 });
$G2 = $obj2->add_group({ title => 'health',  group => $G  });
$G2 = $obj2->add_group({ title => 'web',     group => $G  });
$G3 = $obj2->add_group({ title => 'hosting', group => $G2 });
$G3 = $obj2->add_group({ title => 'mail',    group => $G2 });
$G  = $obj2->add_group({ title => 'Foo'      });
$dump = "\n".eval { $obj2->dump_groups };
$ok = $obj2->parse_db($obj2->gen_db($pass), $pass);
$dump2 = "\n".eval { $obj2->dump_groups };
#diag($dump2);
is($dump2, $dump, "Dumps should match after gen_db->parse_db") && diag($dump);
