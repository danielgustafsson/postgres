# Copyright (c) 2026, PostgreSQL Global Development Group

# Corrupt only a disposable archive, never the primary's pg_wal.  Recovery
# must not expose a partially replayed transaction and must resume when the
# original archived segment becomes available again.

use strict;
use warnings FATAL => 'all';

use File::Copy qw(copy);
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $primary = PostgreSQL::Test::Cluster->new('primary');
$primary->init(
	has_archiving => 1,
	allows_streaming => 1,
	extra => [ '--wal-segsize=1', '--data-checksums' ]);
$primary->append_conf(
	'postgresql.conf', q{
autovacuum = off
checkpoint_timeout = '1h'
});
$primary->start;
$primary->safe_psql(
	'postgres', q{
CREATE TABLE ledger (id integer PRIMARY KEY, value text NOT NULL);
INSERT INTO ledger SELECT i, repeat(md5(i::text), 16)
  FROM generate_series(1, 100) i;
});

my $contents =
  q{SELECT count(*), md5(string_agg(id::text || ':' || value, ',' ORDER BY id))
    FROM ledger};
my $before = $primary->safe_psql('postgres', $contents);
$primary->backup('base');

# Start the transaction in a segment not included in the base backup.
$primary->safe_psql('postgres', 'SELECT pg_switch_wal()');
my $walfile = $primary->safe_psql('postgres',
	'SELECT pg_walfile_name(pg_current_wal_insert_lsn())');
$primary->safe_psql(
	'postgres', q{
BEGIN;
INSERT INTO ledger SELECT i, repeat(md5(i::text), 16)
  FROM generate_series(101, 200) i;
UPDATE ledger SET value = 'updated' WHERE id <= 10;
DELETE FROM ledger WHERE id BETWEEN 11 AND 20;
COMMIT;
});
my $after = $primary->safe_psql('postgres', $contents);
my $target =
  $primary->safe_psql('postgres', 'SELECT pg_current_wal_insert_lsn()');
$primary->safe_psql('postgres', 'SELECT pg_switch_wal()');
my $archive = $primary->archive_dir;
$primary->poll_query_until('postgres',
	"SELECT archived_count > 0 AND last_archived_wal >= '$walfile' FROM pg_stat_archiver"
) or die 'timed out waiting for WAL archiving';
ok(-f "$archive/$walfile", 'transaction WAL has been archived');
ok( !-f $primary->backup_dir . "/base/pg_wal/$walfile",
	'transaction WAL is not in the base backup');
$primary->stop;

# Retain the untouched original outside the archive searched by recovery.
my $saved = PostgreSQL::Test::Utils::tempdir();
copy("$archive/$walfile", "$saved/$walfile") or die "copy WAL: $!";

my ($dump, $stderr);
ok( IPC::Run::run(
		[ 'pg_waldump', '--path', $saved, $walfile ],
		'>' => \$dump,
		'2>' => \$stderr),
	'decode archived transaction WAL');
my ($first_lsn) = $dump =~ /lsn: ([0-9A-F]+\/[0-9A-F]+)/;
die 'no WAL records in archived segment' unless defined $first_lsn;
my (undef, $low) = split('/', $first_lsn);
# Flip a byte of xl_xid, immediately following uint32 xl_tot_len.  This
# preserves record framing but invalidates the record's checksum.
my $flip_offset = hex($low) % (1024 * 1024) + 4;

# The same corpus also exercises permutations of real heap, btree and
# transaction records.  These are structurally valid, not safe to replay.
mkdir "$saved/permuted" or die "mkdir: $!";
command_ok(
	[
		'waldemort', '--mode',
		'permute', '--input',
		"$saved/$walfile", '--output',
		"$saved/permuted/$walfile", '--seed',
		'42',
	],
	'permute real archived WAL records');
my $permuted_dump;
ok( IPC::Run::run(
		[ 'pg_waldump', '--path', "$saved/permuted", $walfile ],
		'>' => \$permuted_dump,
		'2>' => \$stderr),
	'permuted real WAL has valid framing and checksums');

# Only record locations and previous-record links should change.  Check the
# entire multiset of descriptors, including transaction IDs and block refs.
my @inventories;
for my $text ($dump, $permuted_dump)
{
	$text =~ s/lsn: [0-9A-F]+\/[0-9A-F]+, prev [0-9A-F]+\/[0-9A-F]+, //g;
	push @inventories, [ sort split(/\n/, $text) ];
}
is_deeply($inventories[1], $inventories[0],
	'permutation retains every complete record and its resource-manager data'
);

sub new_standby
{
	my ($name) = @_;
	my $node = PostgreSQL::Test::Cluster->new($name);
	$node->init_from_backup($primary, 'base', has_restoring => 1);
	$node->append_conf(
		'postgresql.conf', q{
wal_retrieve_retry_interval = '100ms'
log_min_messages = debug1
});
	return $node;
}

sub caught_up
{
	my ($node) = @_;
	$node->poll_query_until('postgres',
		"SELECT pg_last_wal_replay_lsn() >= '$target'::pg_lsn")
	  or die 'timed out waiting for archive replay';
	is($node->safe_psql('postgres', $contents),
		$after,
		$node->name . ': complete recovered data matches the primary');
}

my $control = new_standby('control');
$control->start;
caught_up($control);
$control->stop;

my @cases = (
	[
		'bitflip',
		[ '--mode', 'bitflip', '--offset', $flip_offset, '--mask', '1' ],
		qr/incorrect resource manager data checksum/,
	],
	[
		'mixed',
		[ '--mode', 'mixed' ],
		qr/incorrect resource manager data checksum/,
	],
	[
		'headers',
		[ '--mode', 'headers' ],
		qr/invalid record length|invalid resource manager ID|incorrect prev-link/,
	],
	[ 'garbage', [ '--mode', 'garbage' ], qr/invalid magic number/, ],
	[
		'truncate',
		[ '--mode', 'truncate', '--length', '100' ],
		qr/archive file .* has wrong size/,
	],);

for my $case (@cases)
{
	my ($name, $options, $error) = @$case;
	my $broken = "$saved/$name";
	command_ok(
		[
			'waldemort', '--input', "$saved/$walfile", '--output',
			$broken, @$options,
		],
		"$name: corrupt a copy of archived WAL");
	unlink "$archive/$walfile" or die "unlink archive: $!";
	copy($broken, "$archive/$walfile") or die "copy broken WAL: $!";

	my $node = new_standby($name);
	$node->start;
	$node->wait_for_log($error);
	is($node->safe_psql('postgres', 'SELECT pg_is_in_recovery()'),
		't', "$name: remains in recovery");
	is($node->safe_psql('postgres', $contents),
		$before, "$name: no partial transaction is visible");
	is( $node->safe_psql(
			'postgres', "SELECT pg_last_wal_replay_lsn() < '$target'::pg_lsn"
		),
		't',
		"$name: replay does not advance past corruption");

	# Publish the repaired archive by rename, so restore_command never
	# observes a partially copied file.  No standby restart is needed.
	copy("$saved/$walfile", "$archive/repaired") or die "copy original: $!";
	unlink "$archive/$walfile" or die "unlink broken archive: $!";
	rename("$archive/repaired", "$archive/$walfile")
	  or die "rename repaired archive: $!";
	caught_up($node);
	$node->promote;
	is($node->safe_psql('postgres', $contents),
		$after, "$name: data intact after promotion");
	$node->stop;
	command_ok(
		[ 'pg_checksums', '--check', '--pgdata', $node->data_dir ],
		"$name: recovered data pages have valid checksums");
	$node->start;
	is($node->safe_psql('postgres', $contents),
		$after, "$name: recovered data survives a restart");
	$node->stop;
}

done_testing();
