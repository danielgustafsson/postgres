/*-------------------------------------------------------------------------
 *
 * waldemort.c
 *		Generate and mutate disposable WAL segments for testing.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		src/test/modules/waldemort/waldemort.c
 *
 *-------------------------------------------------------------------------
 */
#define FRONTEND 1
#include "postgres.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "access/xlog_internal.h"
#include "access/xlogreader.h"
#include "catalog/pg_control.h"
#include "common/fe_memutils.h"
#include "common/logging.h"
#include "getopt_long.h"

/* Bound memory consumption independently of the segment size. */
#define MAX_RECORD_BYTES (16 * 1024 * 1024)
#define MAX_IMPORTED_BYTES (64 * 1024 * 1024)
#define MAX_RECORDS 1000000
#define MAX_TYPES 32

typedef enum Mode
{
	MODE_VALID,
	MODE_MIXED,
	MODE_HEADERS,
	MODE_GARBAGE,
	MODE_BITFLIP,
	MODE_TRUNCATE,
	MODE_PERMUTE
} Mode;

typedef struct Options
{
	Mode		mode;
	const char *input;
	const char *output;
	uint64		seed;
	uint32		segsize;
	uint64		segno;
	TimeLineID	timeline;
	uint64		sysid;
	XLogRecPtr	prev;
	uint32		records;
	uint32		payload;
	uint64		offset;
	uint64		length;
	uint8		mask;
	uint8		types[MAX_TYPES];
	int			ntypes;
} Options;

typedef struct Input
{
	FILE	   *file;
	uint32		size;
	XLogRecPtr	base;
	char	   *page;
	uint32		pageoff;
	bool		loaded;
	XLogReaderState *reader;
} Input;

typedef struct RecordSet
{
	XLogRecord **records;
	uint32	   *crc_offsets;
	uint32		count;
	uint32		capacity;
	size_t		bytes;
} RecordSet;

static const char *unfinished_output;
static uint64 random_state;

static void
cleanup_output(void)
{
	if (unfinished_output != NULL)
		unlink(unfinished_output);
}

static uint64
parse_uint(const char *value, uint64 maximum, const char *option)
{
	uint64		result = 0;
	const char *p;

	if (*value == '\0')
		pg_fatal("invalid value for %s: \"%s\"", option, value);
	for (p = value; *p; p++)
	{
		unsigned	digit = (unsigned char) *p - '0';

		if (digit > 9 || result > maximum / 10 ||
			(result == maximum / 10 && digit > maximum % 10))
			pg_fatal("invalid value for %s: \"%s\"", option, value);
		result = result * 10 + digit;
	}
	return result;
}

static uint32
parse_hex(const char *value, size_t len, const char *option)
{
	uint32		result = 0;
	size_t		i;

	if (len == 0 || len > 8)
		pg_fatal("invalid value for %s", option);
	for (i = 0; i < len; i++)
	{
		unsigned	digit;
		char		c = value[i];

		if (c >= '0' && c <= '9')
			digit = c - '0';
		else if (c >= 'a' && c <= 'f')
			digit = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			digit = c - 'A' + 10;
		else
			pg_fatal("invalid value for %s", option);
		result = (result << 4) | digit;
	}
	return result;
}

static XLogRecPtr
parse_lsn(const char *value)
{
	const char *slash = strchr(value, '/');

	if (strcmp(value, "0") == 0)
		return InvalidXLogRecPtr;
	if (slash == NULL)
		pg_fatal("invalid value for --prev: use hexadecimal X/Y or 0");
	return ((uint64) parse_hex(value, slash - value, "--prev") << 32) |
		parse_hex(slash + 1, strlen(slash + 1), "--prev");
}

/* SplitMix64, with specified unsigned arithmetic and byte extraction. */
static uint64
random_u64(void)
{
	uint64		z;

	random_state += UINT64CONST(0x9e3779b97f4a7c15);
	z = random_state;
	z = (z ^ (z >> 30)) * UINT64CONST(0xbf58476d1ce4e5b9);
	z = (z ^ (z >> 27)) * UINT64CONST(0x94d049bb133111eb);
	return z ^ (z >> 31);
}

static void
random_bytes(char *dest, size_t len)
{
	while (len > 0)
	{
		uint64		value = random_u64();
		int			i;

		for (i = 0; i < 8 && len > 0; i++, len--)
		{
			*dest++ = (char) (value & 0xff);
			value >>= 8;
		}
	}
}

static uint32
random_below(uint32 limit)
{
	uint64		value;
	uint64		threshold = (UINT64CONST(0) - limit) % limit;

	do
	{
		value = random_u64();
	} while (value < threshold);
	return value % limit;
}

static void
usage(void)
{
	printf("WALdemort generates and mutates disposable PostgreSQL WAL segments.\n\n"
		   "Usage: waldemort --output PATH [OPTION ...]\n\n"
		   "  --mode MODE          valid (default), mixed, headers, garbage,\n"
		   "                       bitflip, truncate, or permute\n"
		   "  --input PATH         existing segment (required for last three modes)\n"
		   "  --output PATH        exclusively create this file; never overwrite\n"
		   "  --seed N             deterministic random seed (default 1)\n"
		   "  --seg-size MB        segment size, power of two, 1..1024 (default 16)\n"
		   "  --segno N            segment number (default 1)\n"
		   "  --timeline N         nonzero timeline ID (default 1)\n"
		   "  --system-id N        system identifier (default 1)\n"
		   "  --prev X/Y           first record's previous LSN (default 0)\n"
		   "  --records N          synthetic records, plus a SWITCH (default 32)\n"
		   "  --payload-size N     NOOP main data bytes (default 32)\n"
		   "  --types LIST         repeating noop,restore-point list (default noop)\n"
		   "  --offset N           bitflip byte offset (required for bitflip)\n"
		   "  --mask N             bitflip XOR mask, 1..255 or 0xFF (default 1)\n"
		   "  --length N           truncate output length (required for truncate)\n"
		   "  --help               show this help\n"
		   "  --version            show version\n\n"
		   "WARNING: structural validity does not imply safe replay. Use only\n"
		   "disposable test archives, never production WAL or database clusters.\n");
}

static void
parse_types(Options *opt, const char *value)
{
	const char *start = value;

	opt->ntypes = 0;
	do
	{
		const char *end = strchr(start, ',');
		size_t		len = end ? (size_t) (end - start) : strlen(start);
		uint8		type;

		if (len == strlen("noop") && strncmp(start, "noop", len) == 0)
			type = XLOG_NOOP;
		else if (len == strlen("restore-point") &&
				 strncmp(start, "restore-point", len) == 0)
			type = XLOG_RESTORE_POINT;
		else
			pg_fatal("unknown or empty record type in --types: \"%s\"", value);
		if (opt->ntypes == MAX_TYPES)
			pg_fatal("--types permits at most %d entries", MAX_TYPES);
		opt->types[opt->ntypes++] = type;
		start = end ? end + 1 : NULL;
	} while (start != NULL);
}

static void
parse_options(int argc, char **argv, Options *opt)
{
	enum
	{
		OPT_MODE = 256, OPT_INPUT, OPT_OUTPUT, OPT_SEED, OPT_SEGSIZE,
		OPT_SEGNO, OPT_TIMELINE, OPT_SYSID, OPT_PREV, OPT_RECORDS,
		OPT_PAYLOAD, OPT_TYPES, OPT_OFFSET, OPT_MASK, OPT_LENGTH
	};
	static const struct option long_options[] = {
		{"mode", required_argument, NULL, OPT_MODE},
		{"input", required_argument, NULL, OPT_INPUT},
		{"output", required_argument, NULL, OPT_OUTPUT},
		{"seed", required_argument, NULL, OPT_SEED},
		{"seg-size", required_argument, NULL, OPT_SEGSIZE},
		{"segno", required_argument, NULL, OPT_SEGNO},
		{"timeline", required_argument, NULL, OPT_TIMELINE},
		{"system-id", required_argument, NULL, OPT_SYSID},
		{"prev", required_argument, NULL, OPT_PREV},
		{"records", required_argument, NULL, OPT_RECORDS},
		{"payload-size", required_argument, NULL, OPT_PAYLOAD},
		{"types", required_argument, NULL, OPT_TYPES},
		{"offset", required_argument, NULL, OPT_OFFSET},
		{"mask", required_argument, NULL, OPT_MASK},
		{"length", required_argument, NULL, OPT_LENGTH},
		{"help", no_argument, NULL, '?'},
		{"version", no_argument, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};
	bool		seen[OPT_LENGTH - OPT_MODE + 1] = {false};
	int			c;
	int			i;

	memset(opt, 0, sizeof(*opt));
	opt->seed = opt->segno = opt->timeline = opt->sysid = 1;
	opt->segsize = 16 * 1024 * 1024;
	opt->records = opt->payload = 32;
	opt->mask = 1;
	opt->types[0] = XLOG_NOOP;
	opt->ntypes = 1;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "", long_options, NULL)) != -1)
	{
		if (c == '?' && strcmp(argv[optind - 1], "--help") == 0)
		{
			usage();
			exit(EXIT_SUCCESS);
		}
		if (c == 'V')
		{
			printf("WALdemort (PostgreSQL) " PG_VERSION "\n");
			exit(EXIT_SUCCESS);
		}
		if (c < OPT_MODE || c > OPT_LENGTH)
			pg_fatal("unrecognized option or missing argument; use --help");
		if (seen[c - OPT_MODE])
			pg_fatal("option --%s specified more than once",
					 long_options[c - OPT_MODE].name);
		seen[c - OPT_MODE] = true;
		switch (c)
		{
			case OPT_MODE:
				{
					static const char *names[] = {
						"valid", "mixed", "headers", "garbage",
						"bitflip", "truncate", "permute"
					};

					for (i = 0; i < lengthof(names); i++)
						if (strcmp(optarg, names[i]) == 0)
							break;
					if (i == lengthof(names))
						pg_fatal("unknown mode: \"%s\"", optarg);
					opt->mode = (Mode) i;
					break;
				}
			case OPT_INPUT:
				opt->input = optarg;
				break;
			case OPT_OUTPUT:
				opt->output = optarg;
				break;
			case OPT_SEED:
				opt->seed = parse_uint(optarg, PG_UINT64_MAX, "--seed");
				break;
			case OPT_SEGSIZE:
				opt->segsize = parse_uint(optarg, 1024, "--seg-size") * 1024 * 1024;
				if (!IsValidWalSegSize(opt->segsize))
					pg_fatal("--seg-size must be a power of two between 1 and 1024");
				break;
			case OPT_SEGNO:
				opt->segno = parse_uint(optarg, PG_UINT64_MAX, "--segno");
				break;
			case OPT_TIMELINE:
				opt->timeline = parse_uint(optarg, PG_UINT32_MAX, "--timeline");
				if (opt->timeline == 0)
					pg_fatal("--timeline must be nonzero");
				break;
			case OPT_SYSID:
				opt->sysid = parse_uint(optarg, PG_UINT64_MAX, "--system-id");
				break;
			case OPT_PREV:
				opt->prev = parse_lsn(optarg);
				break;
			case OPT_RECORDS:
				opt->records = parse_uint(optarg, MAX_RECORDS, "--records");
				break;
			case OPT_PAYLOAD:
				opt->payload = parse_uint(optarg,
										  MAX_RECORD_BYTES - SizeOfXLogRecord -
										  SizeOfXLogRecordDataHeaderLong,
										  "--payload-size");
				break;
			case OPT_TYPES:
				parse_types(opt, optarg);
				break;
			case OPT_OFFSET:
				opt->offset = parse_uint(optarg, PG_UINT64_MAX, "--offset");
				break;
			case OPT_MASK:
				{
					uint32		mask;

					if (strncmp(optarg, "0x", 2) == 0)
						mask = parse_hex(optarg + 2, strlen(optarg + 2), "--mask");
					else
						mask = parse_uint(optarg, 255, "--mask");
					if (mask == 0 || mask > 255)
						pg_fatal("--mask must be between 1 and 255");
					opt->mask = mask;
					break;
				}
			case OPT_LENGTH:
				opt->length = parse_uint(optarg, PG_UINT64_MAX, "--length");
				break;
		}
	}
	if (optind != argc)
		pg_fatal("unexpected positional argument: \"%s\"", argv[optind]);
	if (opt->output == NULL || *opt->output == '\0')
		pg_fatal("--output is required");
	if (opt->mode >= MODE_BITFLIP && opt->input == NULL)
		pg_fatal("--input is required for this mode");
	if (opt->input && opt->mode == MODE_VALID)
		pg_fatal("--input is not supported in valid mode");
	if (opt->input)
		for (i = OPT_SEGSIZE; i <= OPT_TYPES; i++)
			if (seen[i - OPT_MODE])
				pg_fatal("--%s cannot be used with --input",
						 long_options[i - OPT_MODE].name);
	if (opt->mode == MODE_GARBAGE)
		for (i = OPT_PREV; i <= OPT_TYPES; i++)
			if (seen[i - OPT_MODE])
				pg_fatal("--%s cannot be used in garbage mode",
						 long_options[i - OPT_MODE].name);
	if (seen[OPT_OFFSET - OPT_MODE] != (opt->mode == MODE_BITFLIP))
		pg_fatal("--offset is required only in bitflip mode");
	if (seen[OPT_MASK - OPT_MODE] && opt->mode != MODE_BITFLIP)
		pg_fatal("--mask is only supported in bitflip mode");
	if (seen[OPT_LENGTH - OPT_MODE] != (opt->mode == MODE_TRUNCATE))
		pg_fatal("--length is required only in truncate mode");
}

static void
seek_file(FILE *file, uint32 offset)
{
	if (fseeko(file, offset, SEEK_SET) != 0)
		pg_fatal("could not seek in file: %m");
}

static void
read_bytes(FILE *file, char *data, size_t size)
{
	if (fread(data, 1, size, file) != size)
	{
		if (ferror(file))
			pg_fatal("could not read input: %m");
		pg_fatal("unexpected end of input");
	}
}

static void
write_bytes(FILE *file, const char *data, size_t size)
{
	if (fwrite(data, 1, size, file) != size)
		pg_fatal("could not write output: %m");
}

static void
reader_close(XLogReaderState *reader)
{
	reader->seg.ws_file = -1;
}

static void
open_input(Input *input, Options *opt)
{
	struct stat st;
	XLogLongPageHeaderData header;

	memset(input, 0, sizeof(*input));
	input->file = fopen(opt->input, "rb");
	if (input->file == NULL)
		pg_fatal("could not open input \"%s\": %m", opt->input);
	if (fstat(fileno(input->file), &st) != 0)
		pg_fatal("could not stat input: %m");
	if (!S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > WalSegMaxSize)
		pg_fatal("input must be a regular file no larger than 1 GB");
	input->size = st.st_size;
	/* Raw mutations must also work on already damaged or truncated fixtures. */
	if (opt->mode == MODE_BITFLIP || opt->mode == MODE_TRUNCATE)
		return;
	if (opt->mode == MODE_GARBAGE)
	{
		if (!IsValidWalSegSize(input->size))
			pg_fatal("garbage input length must be a valid WAL segment size");
		opt->segsize = input->size;
		return;
	}
	if (st.st_size < SizeOfXLogLongPHD)
		pg_fatal("input must be a regular, complete WAL segment");
	read_bytes(input->file, (char *) &header, sizeof(header));
	if (header.std.xlp_magic != XLOG_PAGE_MAGIC ||
		!(header.std.xlp_info & XLP_LONG_HEADER) ||
		(header.std.xlp_info & ~XLP_ALL_FLAGS) != 0 ||
		!IsValidWalSegSize(header.xlp_seg_size) ||
		header.xlp_xlog_blcksz != XLOG_BLCKSZ ||
		st.st_size != header.xlp_seg_size ||
		header.std.xlp_pageaddr % header.xlp_seg_size != 0 ||
		header.std.xlp_tli == 0 ||
		header.std.xlp_pageaddr > PG_UINT64_MAX - header.xlp_seg_size)
		pg_fatal("input has an invalid or incompatible WAL segment header or size");
	opt->segsize = input->size = header.xlp_seg_size;
	input->base = header.std.xlp_pageaddr;
	opt->segno = input->base / opt->segsize;
	opt->timeline = header.std.xlp_tli;
	opt->sysid = header.xlp_sysid;
	input->page = pg_malloc(XLOG_BLCKSZ);
	input->reader = XLogReaderAllocate(opt->segsize, NULL,
									   XL_ROUTINE(.segment_close = reader_close),
									   NULL);
	if (input->reader == NULL)
		pg_fatal("could not allocate WAL reader");
	input->reader->system_identifier = opt->sysid;
	input->reader->seg.ws_tli = opt->timeline;
}

static XLogPageHeader
input_page(Input *input, uint32 offset)
{
	if (!input->loaded || input->pageoff != offset)
	{
		Assert(offset % XLOG_BLCKSZ == 0 && offset < input->size);
		seek_file(input->file, offset);
		read_bytes(input->file, input->page, XLOG_BLCKSZ);
		if (!XLogReaderValidatePageHeader(input->reader, input->base + offset,
										  input->page))
			pg_fatal("invalid input page: %s", input->reader->errormsg_buf);
		if (((XLogPageHeader) input->page)->xlp_info &
			XLP_FIRST_IS_OVERWRITE_CONTRECORD)
			pg_fatal("overwrite continuation pages are not supported");
		input->pageoff = offset;
		input->loaded = true;
	}
	return (XLogPageHeader) input->page;
}

/*
 * Copy raw record bytes, not XLogReadRecord()'s decoded header.  In particular,
 * a raw record's header can itself straddle pages.  A NULL destination skips a
 * leading continuation without allocating memory for an unavailable record.
 */
static bool
copy_record(Input *input, uint32 *position, uint32 length, char *dest)
{
	uint32		remaining = length;

	while (remaining > 0)
	{
		uint32		pageoff;
		uint32		off;
		uint32		amount;
		XLogPageHeader header;

		if (*position >= input->size)
			return false;
		pageoff = *position - *position % XLOG_BLCKSZ;
		header = input_page(input, pageoff);
		off = *position % XLOG_BLCKSZ;
		if (off == 0)
		{
			if (!(header->xlp_info & XLP_FIRST_IS_CONTRECORD) ||
				header->xlp_rem_len != remaining)
				pg_fatal("invalid continuation at input offset %u", pageoff);
			off = XLogPageHeaderSize(header);
			*position += off;
		}
		amount = Min(remaining, XLOG_BLCKSZ - off);
		if (dest)
		{
			memcpy(dest, input->page + off, amount);
			dest += amount;
		}
		*position += amount;
		remaining -= amount;
	}
	*position = MAXALIGN(*position);
	return true;
}

static pg_crc32c
record_crc(XLogRecord *record)
{
	pg_crc32c	crc;

	INIT_CRC32C(crc);
	COMP_CRC32C(crc, (char *) record + SizeOfXLogRecord,
				record->xl_tot_len - SizeOfXLogRecord);
	COMP_CRC32C(crc, (char *) record, offsetof(XLogRecord, xl_crc));
	FIN_CRC32C(crc);
	return crc;
}

static bool
zero_tail(Input *input, uint32 position)
{
	char		buf[XLOG_BLCKSZ];

	seek_file(input->file, position);
	while (position < input->size)
	{
		uint32		len = Min((uint32) sizeof(buf), input->size - position);
		uint32		i;

		read_bytes(input->file, buf, len);
		for (i = 0; i < len; i++)
			if (buf[i] != 0)
				return false;
		position += len;
	}
	return true;
}

/*
 * DecodeXLogRecord accumulates fragment lengths in a uint32.  Bound the long
 * main-data length before calling it, so even a deliberately forged CRC cannot
 * make that sum wrap.  Leave all other encoding checks to the real decoder.
 */
static bool
bounded_main_data(XLogRecord *record)
{
	const unsigned char *ptr = (unsigned char *) record + SizeOfXLogRecord;
	size_t		remaining = record->xl_tot_len - SizeOfXLogRecord;
	uint64		datatotal = 0;

	while (remaining > datatotal)
	{
		uint8		id = *ptr++;
		size_t		skip;

		remaining--;
		if (id == XLR_BLOCK_ID_DATA_LONG)
		{
			uint32		length;

			if (remaining < sizeof(length))
				return true;
			memcpy(&length, ptr, sizeof(length));
			return length <= record->xl_tot_len;
		}
		if (id == XLR_BLOCK_ID_DATA_SHORT)
			return true;
		if (id == XLR_BLOCK_ID_ORIGIN)
			skip = sizeof(ReplOriginId);
		else if (id == XLR_BLOCK_ID_TOPLEVEL_XID)
			skip = sizeof(TransactionId);
		else if (id <= XLR_MAX_BLOCK_ID)
		{
			uint8		flags;
			uint16		length;

			skip = SizeOfXLogRecordBlockHeader - sizeof(uint8);
			if (remaining < skip)
				return true;
			flags = *ptr;
			memcpy(&length, ptr + sizeof(uint8), sizeof(length));
			datatotal += length;
			ptr += skip;
			remaining -= skip;
			if (flags & BKPBLOCK_HAS_IMAGE)
			{
				uint8		info;

				if (remaining < SizeOfXLogRecordBlockImageHeader)
					return true;
				memcpy(&length, ptr, sizeof(length));
				datatotal += length;
				info = ptr[offsetof(XLogRecordBlockImageHeader, bimg_info)];
				ptr += SizeOfXLogRecordBlockImageHeader;
				remaining -= SizeOfXLogRecordBlockImageHeader;
				if (BKPIMAGE_COMPRESSED(info) && (info & BKPIMAGE_HAS_HOLE))
				{
					if (remaining < SizeOfXLogRecordBlockCompressHeader)
						return true;
					ptr += SizeOfXLogRecordBlockCompressHeader;
					remaining -= SizeOfXLogRecordBlockCompressHeader;
				}
			}
			skip = sizeof(BlockNumber);
			if (!(flags & BKPBLOCK_SAME_REL))
				skip += sizeof(RelFileLocator);
		}
		else
			return true;
		if (remaining < skip)
			return true;
		ptr += skip;
		remaining -= skip;
	}
	return true;
}

static uint32
record_byte_offset(Input *input, uint32 start, uint32 offset)
{
	for (;;)
	{
		uint32		available = XLOG_BLCKSZ - start % XLOG_BLCKSZ;

		if (offset < available)
			return start + offset;
		offset -= available;
		start += available;
		start += XLogPageHeaderSize(input_page(input, start));
	}
}

static RecordSet
import_records(Input *input, Options *opt)
{
	RecordSet	set = {0};
	uint32		pos = SizeOfXLogLongPHD;
	XLogRecPtr	previous = InvalidXLogRecPtr;
	XLogPageHeader first = input_page(input, 0);

	if (first->xlp_info & XLP_FIRST_IS_CONTRECORD)
	{
		uint32		remaining = first->xlp_rem_len;

		if (remaining == 0 || remaining > XLogRecordMaxSize)
			pg_fatal("invalid leading continuation length");
		if (!copy_record(input, &pos, remaining, NULL))
			pg_fatal("input contains no complete records");
	}
	else if (first->xlp_rem_len != 0)
		pg_fatal("unexpected continuation length in first page");

	while (pos < input->size)
	{
		uint32		start;
		uint32		length;
		XLogRecord *record;
		DecodedXLogRecord *decoded;
		char	   *error = NULL;
		pg_crc32c	crc;

		if (pos % XLOG_BLCKSZ == 0)
		{
			XLogPageHeader header;

			/* Unwritten tails of an otherwise complete segment are allowed. */
			if (zero_tail(input, pos))
				break;
			header = input_page(input, pos);
			if ((header->xlp_info & XLP_FIRST_IS_CONTRECORD) ||
				header->xlp_rem_len != 0)
				pg_fatal("unexpected continuation at input offset %u", pos);
			pos += XLogPageHeaderSize(header);
		}
		start = pos;
		input_page(input, pos - pos % XLOG_BLCKSZ);
		memcpy(&length, input->page + pos % XLOG_BLCKSZ, sizeof(length));
		if (length == 0 && zero_tail(input, pos))
			break;
		if (length < SizeOfXLogRecord || length > XLogRecordMaxSize)
			pg_fatal("invalid record length at input offset %u", start);
		if (length > MAX_RECORD_BYTES)
			pg_fatal("input record exceeds the %d-byte record limit", MAX_RECORD_BYTES);
		record = pg_malloc(length);
		if (!copy_record(input, &pos, length, (char *) record))
		{
			pg_free(record);
			break;				/* trailing cross-segment record */
		}
		if (!RmgrIdIsValid(record->xl_rmid) ||
			record->xl_prev >= input->base + start ||
			(previous != InvalidXLogRecPtr && record->xl_prev != previous))
			pg_fatal("invalid record header or previous link at input offset %u", start);
		crc = record_crc(record);
		if (!EQ_CRC32C(crc, record->xl_crc))
			pg_fatal("incorrect record checksum at input offset %u", start);
		if (!bounded_main_data(record))
			pg_fatal("invalid main-data length at input offset %u", start);
		decoded = pg_malloc(DecodeXLogRecordRequiredSpace(length));
		decoded->oversized = false;
		input->reader->ReadRecPtr = input->base + start;
		if (!DecodeXLogRecord(input->reader, decoded, record,
							  input->base + start, &error))
			pg_fatal("invalid input record: %s", error);
		pg_free(decoded);
		if (record->xl_rmid == RM_XLOG_ID &&
			(record->xl_info & ~XLR_INFO_MASK) == XLOG_SWITCH)
		{
			pg_free(record);
			break;
		}
		if (set.count == MAX_RECORDS ||
			set.bytes > MAX_IMPORTED_BYTES - length)
			pg_fatal("input exceeds the import limit (%d records or %d bytes)",
					 MAX_RECORDS, MAX_IMPORTED_BYTES);
		if (set.count == set.capacity)
		{
			set.capacity = set.capacity ? Min(set.capacity * 2, MAX_RECORDS) : 1024;
			set.records = pg_realloc(set.records, set.capacity * sizeof(XLogRecord *));
			if (opt->mode == MODE_MIXED)
				set.crc_offsets = pg_realloc(set.crc_offsets,
											 set.capacity * sizeof(uint32));
		}
		if (set.count == 0)
			opt->prev = record->xl_prev;
		if (opt->mode == MODE_MIXED)
		{
			set.crc_offsets[set.count] =
				record_byte_offset(input, start, offsetof(XLogRecord, xl_crc));
			pg_free(record);
			record = NULL;
		}
		set.records[set.count++] = record;
		set.bytes += length;
		previous = input->base + start;
	}
	if (set.count == 0)
		pg_fatal("input contains no complete non-SWITCH records");
	/* A skipped continuation may have started in this segment's predecessor. */
	if (opt->prev >= input->base + SizeOfXLogLongPHD)
		opt->prev = InvalidXLogRecPtr;
	for (uint32 i = opt->mode == MODE_PERMUTE ? set.count : 0; i > 1; i--)
	{
		uint32		j = random_below(i);
		XLogRecord *record = set.records[i - 1];

		set.records[i - 1] = set.records[j];
		set.records[j] = record;
	}
	return set;
}

static uint32
payload_length(const Options *opt, uint8 type)
{
	if (type == XLOG_SWITCH)
		return 0;
	if (type == XLOG_RESTORE_POINT)
		return sizeof(xl_restore_point);
	return opt->payload;
}

static uint32
synthetic_length(const Options *opt, uint8 type)
{
	uint32		payload = payload_length(opt, type);

	return SizeOfXLogRecord + payload +
		(payload == 0 ? 0 : payload <= UINT8_MAX ?
		 SizeOfXLogRecordDataHeaderShort : SizeOfXLogRecordDataHeaderLong);
}

static XLogRecord *
make_record(const Options *opt, uint8 type, uint32 number)
{
	uint32		payload = payload_length(opt, type);
	uint32		length = synthetic_length(opt, type);
	XLogRecord *record = pg_malloc0(length);
	char	   *ptr = (char *) record + SizeOfXLogRecord;

	record->xl_tot_len = length;
	record->xl_rmid = RM_XLOG_ID;
	record->xl_info = type;
	if (payload > 0)
	{
		if (payload <= UINT8_MAX)
		{
			*ptr++ = XLR_BLOCK_ID_DATA_SHORT;
			*ptr++ = (uint8) payload;
		}
		else
		{
			*ptr++ = XLR_BLOCK_ID_DATA_LONG;
			memcpy(ptr, &payload, sizeof(payload));
			ptr += sizeof(payload);
		}
		if (type == XLOG_RESTORE_POINT)
		{
			xl_restore_point restore;

			memset(&restore, 0, sizeof(restore));
			restore.rp_time = (TimestampTz) number * USECS_PER_SEC;
			snprintf(restore.rp_name, sizeof(restore.rp_name),
					 "waldemort-%u", number);
			memcpy(ptr, &restore, sizeof(restore));
		}
		else
			random_bytes(ptr, payload);
	}
	return record;
}

static void
make_page_header(char *page, uint32 offset, const Options *opt)
{
	XLogPageHeader header = (XLogPageHeader) page;

	memset(page, 0, offset == 0 ? SizeOfXLogLongPHD : SizeOfXLogShortPHD);
	header->xlp_magic = XLOG_PAGE_MAGIC;
	header->xlp_tli = opt->timeline;
	header->xlp_pageaddr = opt->segno * opt->segsize + offset;
	if (offset == 0)
	{
		XLogLongPageHeader longheader = (XLogLongPageHeader) page;

		header->xlp_info = XLP_LONG_HEADER;
		longheader->xlp_sysid = opt->sysid;
		longheader->xlp_seg_size = opt->segsize;
		longheader->xlp_xlog_blcksz = XLOG_BLCKSZ;
	}
}

/*
 * The same layout calculation is used for preflight and writing, including
 * split record headers and MAXALIGN padding.  Never silently drop records.
 */
static uint32
place_record(FILE *file, const Options *opt, uint32 pos,
			 XLogRecord *record, uint32 length, XLogRecPtr *previous,
			 bool corrupt)
{
	uint32		remaining = length;
	const char *data = (const char *) record;
	XLogRecPtr	start;

	if (pos % XLOG_BLCKSZ == 0)
		pos += pos == 0 ? SizeOfXLogLongPHD : SizeOfXLogShortPHD;
	start = opt->segno * opt->segsize + pos;
	if (file)
	{
		record->xl_prev = *previous;
		record->xl_crc = record_crc(record);
		if (corrupt)
		{
			if (opt->input == NULL && length > SizeOfXLogRecord)
				((char *) record)[length - 1] ^= 1;
			else
				record->xl_crc ^= 1;
		}
		*previous = start;
	}
	while (remaining > 0)
	{
		uint32		amount;

		if (pos >= opt->segsize)
			pg_fatal("records and terminal SWITCH do not fit in one segment");
		if (pos % XLOG_BLCKSZ == 0)
		{
			if (file)
			{
				char	   *page = pg_malloc0(SizeOfXLogShortPHD);
				XLogPageHeader header = (XLogPageHeader) page;

				make_page_header(page, pos, opt);
				header->xlp_info |= XLP_FIRST_IS_CONTRECORD;
				header->xlp_rem_len = remaining;
				seek_file(file, pos);
				write_bytes(file, page, SizeOfXLogShortPHD);
				pg_free(page);
			}
			pos += SizeOfXLogShortPHD;
		}
		amount = Min(remaining, XLOG_BLCKSZ - pos % XLOG_BLCKSZ);
		if (file)
		{
			seek_file(file, pos);
			write_bytes(file, data, amount);
			data += amount;
		}
		pos += amount;
		remaining -= amount;
	}
	return MAXALIGN(pos);
}

static void
write_records(FILE *file, const Options *opt, RecordSet *set)
{
	uint32		pos = 0;
	uint32		count = opt->mode == MODE_PERMUTE ? set->count : opt->records;
	XLogRecPtr	previous = opt->prev;
	uint32		i;

	for (i = 0; i <= count; i++)
	{
		uint8		type = i == count ? XLOG_SWITCH : opt->types[i % opt->ntypes];
		XLogRecord *record = NULL;
		uint32		length;
		bool		imported = opt->mode == MODE_PERMUTE && i < count;

		if (imported)
		{
			record = set->records[i];
			length = record->xl_tot_len;
		}
		else
		{
			length = synthetic_length(opt, type);
			if (file)
				record = make_record(opt, type, i);
		}
		pos = place_record(file, opt, pos, record, length, &previous,
						   opt->mode == MODE_MIXED && i < count && i % 2 == 1);
		if (!imported && record)
			pg_free(record);
	}
}

static FILE *
create_output(const char *path)
{
	int			fd;
	FILE	   *file;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | PG_BINARY, 0600);
	if (fd < 0)
		pg_fatal("could not exclusively create output \"%s\": %m", path);
	unfinished_output = path;
	file = fdopen(fd, "wb");
	if (file == NULL)
	{
		int			save_errno = errno;

		close(fd);
		errno = save_errno;
		pg_fatal("could not open output stream: %m");
	}
	return file;
}

static void
fill_output(FILE *file, const Options *opt)
{
	char	   *page = pg_malloc0(XLOG_BLCKSZ);
	uint32		pos;

	for (pos = 0; pos < opt->segsize; pos += XLOG_BLCKSZ)
	{
		if (opt->mode == MODE_GARBAGE)
			random_bytes(page, XLOG_BLCKSZ);
		else
		{
			memset(page, 0, XLOG_BLCKSZ);
			make_page_header(page, pos, opt);
		}
		write_bytes(file, page, XLOG_BLCKSZ);
	}
	pg_free(page);
}

static void
mutate_input(FILE *output, Input *input, const Options *opt, RecordSet *set)
{
	char	   *page = pg_malloc(XLOG_BLCKSZ);
	uint32		length = opt->mode == MODE_TRUNCATE ? opt->length : input->size;
	uint32		pos;
	uint32		next_damage = 1;

	seek_file(input->file, 0);
	for (pos = 0; pos < length; pos += XLOG_BLCKSZ)
	{
		uint32		amount = Min((uint32) XLOG_BLCKSZ, length - pos);

		read_bytes(input->file, page, amount);
		if (opt->mode == MODE_HEADERS)
		{
			uint32		headersize = XLogPageHeaderSize((XLogPageHeader) page);

			/* Uninitialized page headers are preserved too. */
			random_bytes(page + headersize, amount - headersize);
		}
		else if (opt->mode == MODE_GARBAGE)
			random_bytes(page, amount);
		else if (opt->mode == MODE_BITFLIP &&
				 opt->offset >= pos && opt->offset < pos + amount)
			page[opt->offset - pos] ^= opt->mask;
		else if (opt->mode == MODE_MIXED)
		{
			while (next_damage < set->count &&
				   set->crc_offsets[next_damage] < pos + amount)
			{
				Assert(set->crc_offsets[next_damage] >= pos);
				page[set->crc_offsets[next_damage] - pos] ^= 1;
				next_damage += 2;
			}
		}
		write_bytes(output, page, amount);
	}
	pg_free(page);
}

/* Randomize generated page bodies without touching continuation metadata. */
static void
randomize_bodies(FILE *output, const Options *opt)
{
	char	   *data = pg_malloc(XLOG_BLCKSZ);
	uint32		pos;

	for (pos = 0; pos < opt->segsize; pos += XLOG_BLCKSZ)
	{
		uint32		headersize = pos == 0 ? SizeOfXLogLongPHD : SizeOfXLogShortPHD;

		random_bytes(data, XLOG_BLCKSZ - headersize);
		seek_file(output, pos + headersize);
		write_bytes(output, data, XLOG_BLCKSZ - headersize);
	}
	pg_free(data);
}

int
main(int argc, char **argv)
{
	Options		opt;
	Input		input = {0};
	RecordSet	set = {0};
	FILE	   *output;
	bool		generate;

	pg_logging_init(argv[0]);
	parse_options(argc, argv, &opt);
	if (atexit(cleanup_output) != 0)
		pg_fatal("could not register output cleanup");
	random_state = opt.seed;
	if (opt.input)
		open_input(&input, &opt);
	if (opt.segno > (PG_UINT64_MAX - opt.segsize) / opt.segsize)
		pg_fatal("segment number would overflow WAL addresses");
	if (opt.prev >= opt.segno * opt.segsize + SizeOfXLogLongPHD)
		pg_fatal("--prev must precede the first output record");
	if (opt.mode == MODE_BITFLIP && opt.offset >= input.size)
		pg_fatal("--offset must be less than the input length");
	if (opt.mode == MODE_TRUNCATE && opt.length > input.size)
		pg_fatal("--length must not exceed the input length");
	if (opt.mode == MODE_PERMUTE || (opt.mode == MODE_MIXED && opt.input))
		set = import_records(&input, &opt);
	generate = opt.mode == MODE_PERMUTE ||
		(opt.input == NULL && opt.mode != MODE_GARBAGE);
	if (generate)
		write_records(NULL, &opt, &set);
	output = create_output(opt.output);
	if (opt.input != NULL && !generate)
		mutate_input(output, &input, &opt, &set);
	else
	{
		fill_output(output, &opt);
		if (generate)
			write_records(output, &opt, &set);
		if (opt.mode == MODE_HEADERS)
			randomize_bodies(output, &opt);
	}
	if (fclose(output) != 0)
		pg_fatal("could not close output \"%s\": %m", opt.output);
	unfinished_output = NULL;
	for (uint32 i = 0; i < set.count; i++)
		pg_free(set.records[i]);
	pg_free(set.records);
	pg_free(set.crc_offsets);
	if (input.file)
	{
		if (fclose(input.file) != 0)
			pg_fatal("could not close input: %m");
		if (input.reader)
			XLogReaderFree(input.reader);
		pg_free(input.page);
	}
	return EXIT_SUCCESS;
}
