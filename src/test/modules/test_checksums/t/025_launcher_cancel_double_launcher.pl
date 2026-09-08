# 101_launcher_cancel_double_launcher.pl
#
# Reproducer for a launcher-lifecycle defect introduced by f19c0ec
# ("Online enabling and disabling of data checksums").
#
# THE DEFECT
#   Cancelling (SIGINT / pg_cancel_backend) an in-progress ENABLE launcher
#   makes DataChecksumsWorkerLauncherMain() fall through to its `done:` label,
#   which clears DataChecksumState->launcher_running (datachecksum_state.c:1399)
#   while the cluster state is still "inprogress-on".  The mandatory reset to
#   "off" is deferred to the launcher_exit shmem-exit callback (:1155-1156),
#   which runs SetDataChecksumsOff() -- a long, non-atomic operation (two
#   procsignal barriers + two forced CHECKPOINT_WAIT checkpoints).
#   StartDataChecksumsWorkerLauncher() gates a new launcher solely on
#   launcher_running (:664/:682), so during that window a concurrent
#   pg_enable_data_checksums() starts a SECOND launcher.  The two launchers
#   then race on the checksum state.  The surviving (second) launcher reaches
#   SetDataChecksumsOn() with the state no longer "inprogress-on"; that helper
#   bails with a WARNING ("cannot set data checksums to \"on\" ...") and calls
#   SetDataChecksumsOff(), yet LauncherMain UNCONDITIONALLY logs
#   "data checksums are now enabled" (:1354).  Net result: the server log
#   reports a successful enable while data_checksums and pg_controldata both
#   report OFF -- a false success, and the user's enable is silently lost.
#
#   This breaks the single-launcher invariant the feature was designed around
#   (feature-dev commit bf25e55, which "fixes a bug where the launcher would
#   erroneously revert back to the off state").
#
# We drive the window deterministically with the standard in-tree
# "injection_points" test module (NOT test_checksums): freezing the
# checkpointer at "create-checkpoint-initial" stalls the exit-time
# SetDataChecksumsOff() inside its first forced checkpoint, holding
# launcher_running = false open long enough for the concurrent enable.

use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Keep any accidental stall bounded rather than hanging on the global default.
$PostgreSQL::Test::Utils::timeout_default = 120;

my $node = PostgreSQL::Test::Cluster->new('csum_launcher');
$node->init(no_data_checksums => 1);
$node->append_conf('postgresql.conf', <<'CONF');
shared_buffers = 16MB
max_worker_processes = 16
checkpoint_timeout = 1h
max_wal_size = 4GB
log_min_messages = info
CONF
$node->start;

# injection_points is a standard in-tree test module, not test_checksums.
$node->safe_psql('postgres', 'CREATE EXTENSION injection_points;');

sub csum_state
{
	return $_[0]->safe_psql('postgres',
		"SELECT setting FROM pg_settings WHERE name = 'data_checksums'");
}

sub launcher_pid
{
	return $_[0]->safe_psql('postgres',
		    "SELECT coalesce((SELECT pid FROM pg_stat_activity"
		  . " WHERE backend_type = 'datachecksums launcher' LIMIT 1)::text, '')");
}

# ---- setup (all of this must PASS) --------------------------------------
is(csum_state($node), 'off', 'setup: cluster starts with checksums off');
my $logstart = -s $node->logfile;

# A never-ending open transaction so any ENABLE launcher parks in
# WaitForAllTransactionsToFinish() while the state is "inprogress-on".
my $holder = $node->background_psql('postgres');
$holder->query_safe('BEGIN');
$holder->query_safe('SELECT txid_current()');

# Session A: start ENABLE launcher L1.  It reaches "inprogress-on" and parks.
$node->safe_psql('postgres', 'SELECT pg_enable_data_checksums(0, 100)');
ok( $node->poll_query_until(
		'postgres',
		"SELECT setting FROM pg_settings WHERE name = 'data_checksums'",
		'inprogress-on'),
	'setup: launcher L1 moved the cluster to inprogress-on');
ok( $node->poll_query_until(
		'postgres',
		"SELECT count(*) > 0 FROM pg_stat_activity"
		  . " WHERE backend_type = 'datachecksums launcher'"
		  . " AND query LIKE 'Waiting for transactions older than%'"),
	'setup: launcher L1 parked waiting for the open transaction');
my $l1 = launcher_pid($node);
note "L1 launcher pid = $l1";

# Freeze the checkpointer so L1's exit-time SetDataChecksumsOff() blocks inside
# its first forced checkpoint, holding launcher_running = false open.
$node->safe_psql('postgres',
	"SELECT injection_points_attach('create-checkpoint-initial', 'wait')");

# ---- open the window: cancel L1 -----------------------------------------
# pg_cancel_backend -> abort_requested -> ProcessAllDatabases() returns false
# -> `done:` clears launcher_running (state still inprogress-on) -> proc_exit
# -> launcher_exit -> SetDataChecksumsOff() -> blocks in RequestCheckpoint.
$node->safe_psql('postgres', "SELECT pg_cancel_backend($l1)");
$node->wait_for_event('checkpointer', 'create-checkpoint-initial');

# The exit-time disable has published "inprogress-off" and is now stalled in
# the checkpoint, with launcher_running already cleared.  (Confirms the window
# is open.)
ok( $node->poll_query_until(
		'postgres',
		"SELECT setting FROM pg_settings WHERE name = 'data_checksums'",
		'inprogress-off'),
	'window open: L1 cleared launcher_running and began the exit-time disable (inprogress-off)');

# ---- a concurrent enable starts a SECOND launcher (corroborating) -------
# These next checks PASS only because the defect is present; a correct
# single-launcher implementation would refuse to start a second launcher here.
$node->safe_psql('postgres', 'SELECT pg_enable_data_checksums(0, 100)');
ok( $node->poll_query_until(
		'postgres',
		"SELECT count(*) FROM pg_stat_activity"
		  . " WHERE backend_type = 'datachecksums launcher' AND pid <> $l1",
		'1'),
	'corroborating: a SECOND launcher started while L1 was still exiting');
my $l2 = launcher_pid($node);
note "L2 launcher pid = $l2";
ok($l2 ne '' && $l2 ne $l1,
	"corroborating: launcher pid changed L1=$l1 -> L2=$l2 (single-launcher invariant broken)");
ok( $node->poll_query_until(
		'postgres',
		"SELECT setting FROM pg_settings WHERE name = 'data_checksums'",
		'inprogress-on'),
	'corroborating: checksum state moved BACKWARDS inprogress-off -> inprogress-on under L2');

# ---- let the two launchers race to completion ---------------------------
# Release the checkpointer: L1 finishes disabling to OFF (clobbering L2's
# inprogress-on) while L2 stays parked on the open transaction.
$node->safe_psql('postgres',
	"SELECT injection_points_wakeup('create-checkpoint-initial')");
$node->safe_psql('postgres',
	"SELECT injection_points_detach('create-checkpoint-initial')");
ok( $node->poll_query_until(
		'postgres',
		"SELECT setting FROM pg_settings WHERE name = 'data_checksums'",
		'off'),
	'L1 finished its exit-time disable: state back to off');

# Release the open transaction so L2 proceeds to SetDataChecksumsOn() while the
# state is 'off'.  The guard fires and disables, but the launcher still logs
# "data checksums are now enabled".
$holder->query_safe('COMMIT');
$holder->quit;
ok( $node->poll_query_until(
		'postgres',
		"SELECT count(*) = 0 FROM pg_stat_activity"
		  . " WHERE backend_type = 'datachecksums launcher'"),
	'both launchers have exited');

my $final = csum_state($node);
note "FINAL data_checksums = $final";

my $log = PostgreSQL::Test::Utils::slurp_file($node->logfile, $logstart);
my $said_enabled = ($log =~ /data checksums are now enabled/) ? 1 : 0;
my $said_warning = ($log =~ /cannot set data checksums to "on"/) ? 1 : 0;
my ($ctl) = run_command([ 'pg_controldata', '-D', $node->data_dir ]);
my ($ctlver) = ($ctl =~ /Data page checksum version:\s+(\d+)/);
$ctlver = defined $ctlver ? $ctlver : '?';
note
  "log says 'now enabled' = $said_enabled; guard WARNING = $said_warning; controldata version = $ctlver";

# Corroborating evidence of the race outcome (both hold only while the defect
# is present):
ok($said_enabled,
	'corroborating: launcher logged "data checksums are now enabled"');
ok($said_warning,
	'corroborating: SetDataChecksumsOn() hit its "current state is not inprogress-on" guard and disabled');
is($final, 'off',
	'corroborating: SHOW data_checksums is off despite the "now enabled" log');
is($ctlver, '0',
	'corroborating: pg_controldata reports checksum version 0 (off)');

# ---- THE DEMONSTRATION --------------------------------------------------
# DEFECT: The launcher must never report "data checksums are now enabled"
# DEFECT: unless data checksums actually reached the "on" state.  A cancelled
# DEFECT: enable followed by a concurrent enable must NOT leave the cluster
# DEFECT: reporting off while the server log claims a successful enable: the
# DEFECT: enable must either succeed (leaving checksums on) or fail loudly --
# DEFECT: never log false success.  Under a correct single-launcher
# DEFECT: implementation this assertion PASSES; on this branch it FAILS
# DEFECT: because the second launcher logs "now enabled" while state is off.
ok( !($said_enabled && $final eq 'off'),
	'DEFECT: launcher must not log "data checksums are now enabled" while checksums are off');

$node->stop;
done_testing();
