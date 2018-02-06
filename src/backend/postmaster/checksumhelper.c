/*-------------------------------------------------------------------------
 *
 * checksumhelper.c
 *	  Backend worker to walk the database and write checksums to pages
 *
 * When enabling data checksums on a database at initdb time, no extra
 * process is required as each page is checksummed, and verified, at
 * accesses.  When enabling checksums on an already running cluster
 * which was not initialized with checksums, this helper worker will
 * ensure that all pages are checksummed before verification of the
 * checksums is turned on.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/checksumhelper.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "catalog/pg_database.h"
#include "lib/ilist.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/checksumhelper.h"
#include "postmaster/fork_process.h"
#include "postmaster/postmaster.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lmgr.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/ps_status.h"
#include "utils/timeout.h"

/*
 * GUCs
 */
int			checksumhelper_max_workers;

typedef struct ChecksumHelperDatabase
{
	Oid			dboid;
	const char *dbname;
} ChecksumHelperDatabase;

/*--------------
 * Structure holding information about a single worker.
 *
 * cwi_links		entry into free list or running list
 * cwi_dboid		Oid of the database the worker is checksumming
 * cwi_tableoid		Oid of the current table being worked on
 * cwi_proc			pointer to PGPROC of the running worker, or NULL
 *
 * All fields are protected by ChecksumHelperLock.
 *---------------
 */
typedef struct ChecksumWorkerInfoData
{
	dlist_node	cwi_links;
	Oid			cwi_dboid;
	Oid			cwi_tableoid;
	PGPROC	   *cwi_proc;
} ChecksumWorkerInfoData;

typedef struct ChecksumWorkerInfoData *ChecksumWorkerInfo;

/*--------------
 *
 * ch_launcherpid
 * ch_freeWorkers
 * ch_runningWorkers
 *--------------
 */
typedef struct ChecksumHelperShmemStruct
{
	pid_t		ch_launcherpid;
	dlist_head	ch_freeWorkers;
	dlist_head	ch_runningWorkers;

} ChecksumHelperShmemStruct;

/* Shared memory segment for checksum helper */
static ChecksumHelperShmemStruct *ChecksumHelperShmem;

/* Type of process */
static bool am_checksumhelper_launcher = false;
static bool am_checksumhelper_worker = false;

/* Signal handling */
static volatile sig_atomic_t got_SIGHUP = false;
static volatile sig_atomic_t got_SIGTERM = false;

/* Loop control */
static int ChecksumHelperTimeout = 300;

/* Bookkeeping for work to do */
static List * DatabaseList = NIL;

/* Worker variables */
static ChecksumWorkerInfo MyWorkerInfo = NULL;

/* Prototypes */
static void ch_sighup_handler(SIGNAL_ARGS);
static void ch_sigterm_handler(SIGNAL_ARGS);
static void BuildDatabaseList(void);
static void FreeChecksumWorkerInfo(int code, Datum arg);
NON_EXEC_STATIC void ChecksumHelperLauncherMain(int argc, char **argv);

/*
 * Main entry point for checksum helper launcher process
 */
int
StartChecksumHelperLauncher(void)
{
	pid_t		ChecksumhelperPID;

#ifdef EXEC_BACKEND
	switch ((ChecksumhelperPID = chlauncher_forkexec()))
#else
	switch ((ChecksumhelperPID = fork_process()))
#endif
	{
		case -1:
			ereport(LOG,
					(errmsg("could not launch checksum helper process: %m")));
			return 0;

#ifndef EXEC_BACKEND
		case 0:
			InitPostmasterChild();

			ClosePostmasterPorts(false);

			ChecksumHelperLauncherMain(0, NULL);
			break;
#endif
			
		default:
			return (int) ChecksumhelperPID;
	}

	/* unreached */
	return 0;
}

NON_EXEC_STATIC void
ChecksumHelperLauncherMain(int argc, char **argv)
{
	bool			done = false;

	am_checksumhelper_launcher = true;

	init_ps_display(pgstat_get_backend_desc(B_CHECKSUMHELPER_LAUNCHER), "", "", "");

	ereport(DEBUG1,
			(errmsg("checksumhelper launcher started")));

	SetProcessingMode(InitProcessing);

	pqsignal(SIGHUP, ch_sighup_handler);
	pqsignal(SIGINT, StatementCancelHandler);
	pqsignal(SIGTERM, ch_sigterm_handler);
	pqsignal(SIGQUIT, quickdie);
	InitializeTimeouts();		/* establishes SIGALRM handler */

	BaseInit();

#ifndef EXEC_BACKEND
	InitProcess();
#endif

	InitPostgres(NULL, InvalidOid, NULL, InvalidOid, NULL);

	SetProcessingMode(NormalProcessing);

	ChecksumHelperShmem->ch_launcherpid = MyProcPid;

	/*
	 * Create a database list.  We don't need to concern ourselves with
	 * rebuilding this list during runtime since any new created database
	 * will be running with checksums turned on from the start.
	 */
	BuildDatabaseList();

	/*
	 * If there are no databases at all to checksum, we can exit immediately
	 * as there is no work to do.
	 */
	if (DatabaseList == NIL || list_length(DatabaseList) == 0)
		goto shutdown;

	/*
	 * Main loop, loop until we've either touched all databases or we are
	 * signalled to exit.
	 */
	while (!got_SIGTERM)
	{
		ChecksumHelperDatabase *db;
		int						rc;

		/* sleep */
		rc = WaitLatch(MyLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   ChecksumHelperTimeout * 1000L /* convert to ms */ ,
					   WAIT_EVENT_CHECKSUMHELPER_LAUNCHER_MAIN);

		ResetLatch(MyLatch);

		if (got_SIGTERM)
			break;

		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);

		/*
		 * If there are no free workers, go back to sleeping on the latch
		 */
		if (dlist_is_empty(&ChecksumHelperShmem->ch_freeWorkers))
			continue;

		/* 
		 * If there are no more databases to backfill checksums on, we can
		 * only sit back and wait for the current workers to exit after which
		 * we are done.
		 */
		if (DatabaseList == NIL || list_length(DatabaseList) == 0)
			continue;

		/*
		 * Start a new worker, and assign a database from the list for it to
		 * process.  We don't need to protect the DatabaseList with a lock
		 * since this is the only place where we alter it.
		 */
		db = (ChecksumHelperDatabase *) lfirst(list_head(DatabaseList));
		DatabaseList = list_delete_first(DatabaseList);

		LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);
		/* TODO: Launch worker */
		LWLockRelease(ChecksumHelperLock);
	}

shutdown:

	/*
	 * If we are done with backfilling the database, bump the pg_control
	 * flag to Normal from InProgress
	 */
	if (done)
		SetDataChecksumsNormal();

	ereport(DEBUG1,
			(errmsg("checksumhelper launcher shutting down")));
	ChecksumHelperShmem->ch_launcherpid = 0;

	proc_exit(0);
}

static void
ch_sighup_handler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGHUP = true;
	SetLatch(MyLatch);

	errno = save_errno;
}

static void
ch_sigterm_handler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGTERM = true;
	SetLatch(MyLatch);

	errno = save_errno;
}

/*
 * IsChecksumHelper{Launcher|Worker}Process
 *		Returns the type of process interrogated
 */
bool
IsChecksumHelperLauncherProcess(void)
{
	return am_checksumhelper_launcher;
}
bool
IsChecksumHelperWorkerProcess(void)
{
	return am_checksumhelper_worker;
}

/*
 * ChecksumHelperShmemSize
 *		Compute required space for checksumhelper-related shared memory
 */
Size
ChecksumHelperShmemSize(void)
{
	Size		size;

	size = sizeof(ChecksumHelperShmemStruct);
	size = MAXALIGN(size);
	size = add_size(size, mul_size(checksumhelper_max_workers,
								   sizeof(ChecksumWorkerInfoData)));
	return size;
}

/*
 * ChecksumHelperShmemInit
 *		Allocate and initialize checksumhelper-related shared memory
 */
void
ChecksumHelperShmemInit(void)
{
	bool		found;

	ChecksumHelperShmem = (ChecksumHelperShmemStruct *)
		ShmemInitStruct("ChecksumHelper Data",
						ChecksumHelperShmemSize(),
						&found);

	if (!IsUnderPostmaster)
	{
		ChecksumWorkerInfo	worker;
		int					i;

		Assert(!found);

		ChecksumHelperShmem->ch_launcherpid = 0;
		dlist_init(&ChecksumHelperShmem->ch_freeWorkers);
		dlist_init(&ChecksumHelperShmem->ch_runningWorkers);

		worker = (ChecksumWorkerInfo) ((char *) ChecksumHelperShmem +
									   MAXALIGN(sizeof(ChecksumHelperShmemStruct)));

		for (i = 0; i < checksumhelper_max_workers; i++)
			dlist_push_head(&ChecksumHelperShmem->ch_freeWorkers,
							&worker[i].cwi_links);
	}
	else
		Assert(found);
}

/*
 * BuildDatabaseList
 *		Compile a list of all currently available databases in the cluster
 *
 * This is intended to create the worklist for the workers to go through, and
 * as we are only concerned with already existing databases we need to ever
 * rebuild this list, which simplifies the coding.
 */
static void
BuildDatabaseList(void)
{
	Relation		rel;
	HeapScanDesc	scan;
	HeapTuple		tup;

	/*
	 * As we are only interested in the databases that exist when we start
	 * the helper, this list should never be rebuilt.
	 */
	Assert(DatabaseList == NIL);

	rel = heap_open(DatabaseRelationId, AccessShareLock);
	scan = heap_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_database		pgdb = (Form_pg_database) GETSTRUCT(tup);
		ChecksumHelperDatabase *db;

		db = (ChecksumHelperDatabase *) palloc(sizeof(ChecksumHelperDatabase));

		db->dboid = HeapTupleGetOid(tup);
		db->dbname = pstrdup(NameStr(pgdb->datname));

		DatabaseList = lappend(DatabaseList, db);
	}

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	CommitTransactionCommand();
}

NON_EXEC_STATIC void
ChecksumWorkerMain(int argc, char **argv)
{
	am_checksumhelper_worker = true;

	init_ps_display(pgstat_get_backend_desc(B_CHECKSUMHELPER_WORKER), "", "", "");

	SetProcessingMode(InitProcessing);

	pqsignal(SIGTERM, die);
	pqsignal(SIGQUIT, quickdie);

	BaseInit();

	SetProcessingMode(NormalProcessing);

	on_shmem_exit(FreeChecksumWorkerInfo, 0);
}

/*
 * FreeChecksumWorkerInfo
 *		Return a worker to the free list
 *
 * The worker struct doesn't contain any allocations, so just reset the
 * values to initial settings.
 */
static void
FreeChecksumWorkerInfo(int code, Datum arg)
{
	if (MyWorkerInfo == NULL)
		return;
	
	LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);

	dlist_delete(&MyWorkerInfo->cwi_links);
	MyWorkerInfo->cwi_dboid = InvalidOid;
	MyWorkerInfo->cwi_proc = NULL;

	dlist_push_head(&ChecksumHelperShmem->ch_freeWorkers,
					&MyWorkerInfo->cwi_links);
	MyWorkerInfo = NULL;

	LWLockRelease(ChecksumHelperLock);
}
