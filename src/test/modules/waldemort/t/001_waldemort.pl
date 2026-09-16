# Copyright (c) 2026, PostgreSQL Global Development Group

use strict;
use warnings FATAL => 'all';

use File::Compare qw(compare);
use PostgreSQL::Test::Utils;
use Test::More;

program_help_ok('waldemort');
program_version_ok('waldemort');
program_options_handling_ok('waldemort');

my $tempdir = PostgreSQL::Test::Utils::tempdir();
my $walfile = '000000010000000000000001';
my $segsize = 1024 * 1024;
my ($blocksize) =
  scan_server_header('pg_config.h', '#define\s+XLOG_BLCKSZ\s+(\d+)');

sub read_binary
{
	my ($path) = @_;
	open(my $fh, '<', $path) or die "open $path: $!";
	binmode($fh);
	local $/;
	my $data = <$fh>;
	close($fh) or die "close $path: $!";
	return $data;
}

sub generate
{
	my ($name, @options) = @_;
	my $dir = "$tempdir/$name";
	mkdir $dir or die "mkdir $dir: $!";
	command_ok(
		['waldemort', '--output', "$dir/$walfile", @options],
		"generate $name");
	return "$dir/$walfile";
}

my @synthetic = (
	'--seg-size', '1', '--records', '6', '--seed', '17',
	'--types', 'noop,restore-point', '--payload-size', $blocksize + 17,
);
my $valid = generate('valid', @synthetic);
is(-s $valid, $segsize, 'valid segment has the requested size');
command_like(
	['pg_waldump', '--limit', '7', $valid],
	qr/NOOP.*RESTORE_POINT.*SWITCH/s,
	'valid records, including page continuations, decode successfully');
my $again = generate('again', @synthetic);
is(compare($valid, $again), 0, 'synthetic generation is reproducible');

my $mixed = generate('mixed', @synthetic, '--mode', 'mixed');
is(-s $mixed, $segsize, 'mixed segment has the requested size');
command_like(
	['pg_waldump', '--limit', '1', $mixed],
	qr/NOOP/,
	'mixed segment begins with a valid record');
command_fails_like(
	['pg_waldump', $mixed],
	qr/incorrect resource manager data checksum/,
	'mixed segment contains an invalid record');

my $headers = generate('headers', @synthetic, '--mode', 'headers');
is(-s $headers, $segsize, 'garbage-body segment has the requested size');
command_fails(['pg_waldump', $headers],
	'correct page headers do not make garbage records valid');

# Determine the actual header sizes from the first record and the difference
# between the C structures, without assuming MAXALIGN or WAL block size.
my ($dump, $stderr);
IPC::Run::run(['pg_waldump', '--limit', '1', $valid],
	'>' => \$dump, '2>' => \$stderr)
  or die "pg_waldump: $stderr";
my ($first_lsn) = $dump =~ /lsn: [0-9A-F]+\/([0-9A-F]+)/;
die 'missing first record LSN' unless defined $first_lsn;
my $long_header = hex($first_lsn) % $segsize;
my $short_header = $long_header - 16;
my $original = read_binary($valid);
my $body_garbage = read_binary($headers);
is(substr($body_garbage, 0, $long_header),
	substr($original, 0, $long_header),
	'long page header is preserved');
is(substr($body_garbage, $blocksize, $short_header),
	substr($original, $blocksize, $short_header),
	'continuation page header is preserved');

my $garbage = generate('garbage', '--mode', 'garbage',
	'--seg-size', '1', '--seed', '42');
is(-s $garbage, $segsize, 'garbage segment has the requested size');
command_fails_like(
	['pg_waldump', $garbage], qr/invalid magic number|could not find a valid record/,
	'garbage is not readable WAL');
my $garbage_again = generate('garbage_again', '--mode', 'garbage',
	'--seg-size', '1', '--seed', '42');
is(compare($garbage, $garbage_again), 0, 'garbage generation is reproducible');
my $different = generate('different', '--mode', 'garbage',
	'--seg-size', '1', '--seed', '43');
isnt(compare($garbage, $different), 0, 'different seeds change garbage');

my $flipped = generate('flipped', '--mode', 'bitflip',
	'--input', $valid, '--offset', '100', '--mask', '128');
my $expected = $original;
substr($expected, 100, 1) = chr(ord(substr($expected, 100, 1)) ^ 128);
ok(read_binary($flipped) eq $expected, 'bitflip changes exactly the requested bit');
my $unflipped = generate('unflipped', '--mode', 'bitflip',
	'--input', $flipped, '--offset', '100', '--mask', '128');
is(compare($valid, $unflipped), 0, 'repeating bitflip restores the original');

my $truncated = generate('truncated', '--mode', 'truncate',
	'--input', $valid, '--length', '100');
is(-s $truncated, 100, 'truncate uses the requested length');
ok(read_binary($truncated) eq substr($original, 0, 100),
	'truncate preserves the prefix');

my $permuted = generate('permuted', '--mode', 'permute',
	'--input', $valid, '--seed', '42');
command_like(
	['pg_waldump', '--limit', '7', $permuted],
	qr/SWITCH/,
	'permuted records retain valid checksums, links and continuation headers');
my $permuted_again = generate('permuted_again', '--mode', 'permute',
	'--input', $valid, '--seed', '42');
is(compare($permuted, $permuted_again), 0, 'permutations are reproducible');
isnt(compare($permuted, $valid), 0, 'permutation changes record order');

my @bad_options = (
	['--mode', 'unknown'],
	['--seg-size', '3'],
	['--records', '0'],
	['--records', '-1'],
	['--seed', '18446744073709551616'],
	['--timeline', '0'],
	['--prev', 'not-an-lsn'],
	['--types', 'not-a-record'],
	['--mode', 'bitflip', '--offset', '0'],
	['--mode', 'bitflip', '--input', $valid],
	['--mode', 'bitflip', '--input', $valid, '--offset', $segsize],
	['--mode', 'bitflip', '--input', $valid, '--offset', '-1'],
	['--mode', 'bitflip', '--input', $valid, '--offset', '0', '--mask', '256'],
	['--mode', 'bitflip', '--input', $valid, '--offset', '0', '--mask', '0'],
	['--mode', 'truncate', '--input', $valid, '--length', $segsize + 1],
	['--mode', 'permute', '--input', $garbage],
	['--mode', 'permute', '--input', $mixed],
);
for my $options (@bad_options)
{
	command_fails(['waldemort', '--output', "$tempdir/rejected", @$options],
		"reject invalid options: @$options");
	ok(!-e "$tempdir/rejected", 'invalid options do not leave output behind');
}
command_fails(['waldemort'], 'output is required');
command_fails(
	[
		'waldemort', '--mode', 'bitflip', '--input', $valid,
		'--output', $valid, '--offset', '0',
	],
	'refuse to overwrite input');
command_fails(['waldemort', '--output', $valid],
	'refuse to overwrite existing output');
ok(read_binary($valid) eq $original, 'original input remains untouched');

done_testing();
