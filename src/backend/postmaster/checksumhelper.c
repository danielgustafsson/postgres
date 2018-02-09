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
#include "postmaster/bgworker.h"
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

// XXX: for sleep() only!
#include <unistd.h>

/*
 * Maximum number of times to try enabling checksums in a specific
 * database before giving up.
 */
#define MAX_ATTEMPTS 4

typedef struct ChecksumHelperShmemStruct
{
	bool		success;

} ChecksumHelperShmemStruct;

/* Shared memory segment for checksum helper */
static ChecksumHelperShmemStruct *ChecksumHelperShmem;

/* Signal handling */
static volatile sig_atomic_t got_SIGTERM = false;

/* Bookkeeping for work to do */
typedef struct ChecksumHelperDatabase
{
	Oid			dboid;
	char   	   *dbname;
	int			attempts;
	bool		success;
} ChecksumHelperDatabase;

/* Prototypes */
static List *BuildDatabaseList(void);
static bool ProcessDatabase(ChecksumHelperDatabase *db);

/*
 * Main entry point for checksum helper launcher process
 */
bool
StartChecksumHelperLauncher(void)
{
	BackgroundWorker bgw;
	BackgroundWorkerHandle *bgw_handle;

	/*
	 * XXX: ensure only one can be started!
	 */

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "ChecksumHelperLauncherMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "checksum helper launcher");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "checksum helper launcher");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = MyProcPid;
	bgw.bgw_main_arg = (Datum) 0;

	if (!RegisterDynamicBackgroundWorker(&bgw, &bgw_handle))
		return false;

	return true;
}

/*
 * Enable checksums in a single database.
 * We do this by launching a dynamic background worker into this database,
 * and waiting for it to finish.
 * We have to do this in a separate worker, since each process can only be
 * connected to one database during it's lifetime.
 */
static bool
ProcessDatabase(ChecksumHelperDatabase *db)
{
	BackgroundWorker bgw;
	BackgroundWorkerHandle *bgw_handle;
	BgwHandleStatus status;
	pid_t pid;

	ChecksumHelperShmem->success = false;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "ChecksumHelperWorkerMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "checksum helper worker");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "checksum helper worker");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = MyProcPid;
	bgw.bgw_main_arg = ObjectIdGetDatum(db->dboid);

	if (!RegisterDynamicBackgroundWorker(&bgw, &bgw_handle))
	{
		ereport(LOG,
				(errmsg("failed to start worker for checksum helper in %s", db->dbname)));
		return false;
	}

	status = WaitForBackgroundWorkerStartup(bgw_handle, &pid);
	if (status != BGWH_STARTED)
	{
		ereport(LOG,
				(errmsg("failed to wait for worker startup for checksum helper in %s", db->dbname)));
		return false;
	}

	ereport(DEBUG1,
			(errmsg("started background worker for checksums in %s", db->dbname)));

	status = WaitForBackgroundWorkerShutdown(bgw_handle);
	if (status != BGWH_STOPPED)
	{
		ereport(LOG,
				(errmsg("failed to wait for worker shutdown for checksum helper in %s", db->dbname)));
		return false;
	}

	ereport(DEBUG1,
		   (errmsg("background worker for checksums in %s completed", db->dbname)));

	return ChecksumHelperShmem->success;
}

void
ChecksumHelperLauncherMain(Datum arg)
{
	List *DatabaseList;

	ereport(DEBUG1,
			(errmsg("checksumhelper launcher started")));

	pqsignal(SIGTERM, die);

	BackgroundWorkerUnblockSignals();

	init_ps_display(pgstat_get_backend_desc(B_CHECKSUMHELPER_LAUNCHER), "", "", "");


	/*
	 * Initialize a connection to shared catalogs only.
	 */
	BackgroundWorkerInitializeConnection(NULL, NULL);

	/*
	 * Create a database list.  We don't need to concern ourselves with
	 * rebuilding this list during runtime since any new created database
	 * will be running with checksums turned on from the start.
	 */
	DatabaseList = BuildDatabaseList();

	/*
	 * If there are no databases at all to checksum, we can exit immediately
	 * as there is no work to do.
	 */
	if (DatabaseList == NIL || list_length(DatabaseList) == 0)
		return;

	while (true)
	{
		List *remaining = NIL;
		ListCell *lc, *lc2;
		List *CurrentDatabases = NIL;

		elog(DEBUG1, "Entering loop, length %i", list_length(DatabaseList));
		foreach (lc, DatabaseList)
		{
			ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);

			elog(DEBUG1, "Looping for %s", db->dbname);
			if (ProcessDatabase(db))
			{
				pfree(db->dbname);
				pfree(db);
			}
			else
			{
				/*
				 * Put failed databases on the remaining list.
				 */
				remaining = lappend(remaining, db);
			}
		}
		elog(DEBUG1, "Loop 1 done");
		list_free(DatabaseList);

		DatabaseList = remaining;
		remaining = NIL;

		/*
		 * DatabaseList now has all databases not yet processed. This can be because
		 * they failed for some reason, or because the database was DROPed between
		 * us getting the database list and trying to process it.
		 * Get a fresh list of databases to detect the second case with.
		 * Any database that still exists but failed we retry for a limited number
		 * of times before giving up. Any database that remains in failed state
		 * after that will fail the entire operation.
		 */
		CurrentDatabases = BuildDatabaseList();

		foreach (lc, DatabaseList)
		{
			ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);
			bool found = false;

			foreach (lc2, CurrentDatabases)
			{
				ChecksumHelperDatabase *db2 = (ChecksumHelperDatabase *) lfirst(lc2);

				if (db->dboid == db2->dboid)
				{
					/* Database still exists, time to give up? */
					if (++db->attempts > MAX_ATTEMPTS)
					{
						/* Disable checksums on cluster, because we failed */
						SetDataChecksumsOff();

						ereport(ERROR,
								(errmsg("failed to enable checksums in %s, giving up.", db->dbname)));
					}
					else
						/* Try again with this db */
						remaining = lappend(remaining, db);
					found = true;
					break;
				}
			}
			if (!found)
			{
				ereport(LOG,
						(errmsg("Database %s dropped, skipping", db->dbname)));
				pfree(db->dbname);
				pfree(db);
			}
		}

		/* Free the extra list of databases */
		foreach (lc, CurrentDatabases)
		{
			ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);
			pfree(db->dbname);
			pfree(db);
		}
		list_free(CurrentDatabases);

		/* All databases processed yet? */
		if (remaining == NIL || list_length(remaining) == 0)
			break;

		DatabaseList = remaining;
	}


	/*
	 * Everything has been processed, so flag checksums enabled.
	 */
	SetDataChecksumsOn();

	ereport(LOG,
			(errmsg("Checksums enabled, checksumhelper launcher shutting down")));
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

	/*
	 * No need to initialize content as struct is never used
	 * globally.
	 */
}


/*
 * BuildDatabaseList
 *		Compile a list of all currently available databases in the cluster
 *
 * This is intended to create the worklist for the workers to go through, and
 * as we are only concerned with already existing databases we need to ever
 * rebuild this list, which simplifies the coding.
 */
static List *
BuildDatabaseList(void)
{
	List		   *DatabaseList = NIL;
	Relation		rel;
	HeapScanDesc	scan;
	HeapTuple		tup;
	MemoryContext	ctx = CurrentMemoryContext;
	MemoryContext   oldctx;

	StartTransactionCommand();

	rel = heap_open(DatabaseRelationId, AccessShareLock);
	scan = heap_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_database		pgdb = (Form_pg_database) GETSTRUCT(tup);
		ChecksumHelperDatabase *db;

		oldctx = MemoryContextSwitchTo(ctx);

		db = (ChecksumHelperDatabase *) palloc(sizeof(ChecksumHelperDatabase));

		db->dboid = HeapTupleGetOid(tup);
		db->dbname = pstrdup(NameStr(pgdb->datname));
		elog(DEBUG1, "Added database %s to list", db->dbname);

		DatabaseList = lappend(DatabaseList, db);

		MemoryContextSwitchTo(oldctx);
	}

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	CommitTransactionCommand();

	return DatabaseList;
}



/*
 * Main function for enabling checksums in a single database
 */
void ChecksumHelperWorkerMain(Datum arg)
{
	Oid dboid = DatumGetObjectId(arg);

	pqsignal(SIGTERM, die);

	BackgroundWorkerUnblockSignals();

	init_ps_display(pgstat_get_backend_desc(B_CHECKSUMHELPER_WORKER), "", "", "");

	ereport(DEBUG1,
		   (errmsg("Checksum worker starting for database oid %d", dboid)));

	sleep(10);

	ChecksumHelperShmem->success = true;

	ereport(DEBUG1,
			(errmsg("Checksum worker completed in database oid %d", dboid)));
}
