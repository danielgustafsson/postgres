/*-------------------------------------------------------------------------
 *
 * checksumhelper.c
 *	  Background worker to walk the database and write checksums to pages
 *
 * When enabling data checksums on a database at initdb time, no extra process
 * is required as each page is checksummed, and verified, at accesses.  When
 * enabling checksums on an already running cluster, which was not initialized
 * with checksums, this helper worker will ensure that all pages are
 * checksummed before verification of the checksums is turned on.
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
#include "catalog/pg_database.h"
#include "commands/vacuum.h"
#include "common/relpath.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "postmaster/bgwriter.h"
#include "postmaster/checksumhelper.h"
#include "storage/bufmgr.h"
#include "storage/checksum.h"
#include "storage/lmgr.h"
#include "storage/ipc.h"
#include "storage/procarray.h"
#include "storage/smgr.h"
#include "tcop/tcopprot.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"
#include "utils/ps_status.h"


typedef enum
{
	SUCCESSFUL = 0,
	ABORTED,
	FAILED
}			ChecksumHelperResult;

typedef struct ChecksumHelperShmemStruct
{
	ChecksumHelperResult success;
	bool		process_shared_catalogs;
	bool		abort;
}			ChecksumHelperShmemStruct;

/* Shared memory segment for checksumhelper */
static ChecksumHelperShmemStruct * ChecksumHelperShmem;

/* Bookkeeping for work to do */
typedef struct ChecksumHelperDatabase
{
	Oid			dboid;
	char	   *dbname;
}			ChecksumHelperDatabase;

typedef struct ChecksumHelperRelation
{
	Oid			reloid;
	char		relkind;
}			ChecksumHelperRelation;

/* Prototypes */
static List *BuildDatabaseList(void);
static List *BuildRelationList(bool include_shared);
static ChecksumHelperResult ProcessDatabase(ChecksumHelperDatabase * db);
static void WaitForAllTransactionsToFinish(void);
static void launcher_cancel_handler(SIGNAL_ARGS);
static void checksumhelper_sighup(SIGNAL_ARGS);

/* GUCs */
int			checksumhelper_cost_limit;
int			checksumhelper_cost_delay;

/* Flags set by signal handlers */
static volatile sig_atomic_t got_SIGHUP = false;

/*
 * Main entry point for checksumhelper launcher process.
 */
bool
ChecksumHelperLauncherRegister(void)
{
	BackgroundWorker bgw;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "ChecksumHelperLauncherMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "checksumhelper launcher");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "checksumhelper launcher");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = 0;
	bgw.bgw_main_arg = (Datum) 0;

	RegisterBackgroundWorker(&bgw);

	return true;
}

/*
 * ShutdownChecksumHelperIfRunning
 *		Request shutdown of the checksumhelper
 *
 * This does not turn off processing immediately, it signals the checksum
 * process to end when done with the current block.
 */
void
ShutdownChecksumHelperIfRunning(void)
{
	ChecksumHelperShmem->abort = true;
}

/*
 * ProcessSingleRelationFork
 *		Enable checksums in a single relation/fork.
 *
 * Loops over all existing blocks in this fork and calculates the checksum on them,
 * and writes them out. For any blocks added by another process extending this
 * fork while we run checksums will already set by the process extending it,
 * so we don't need to care about those.
 *
 * Returns true if successful, and false if *aborted*. On error, an actual
 * error is raised in the lower levels.
 */
static bool
ProcessSingleRelationFork(Relation reln, ForkNumber forkNum, BufferAccessStrategy strategy)
{
	BlockNumber numblocks = RelationGetNumberOfBlocksInFork(reln, forkNum);
	BlockNumber b;
	char		activity[NAMEDATALEN * 2 + 128];

	for (b = 0; b < numblocks; b++)
	{
		Buffer		buf = ReadBufferExtended(reln, forkNum, b, RBM_NORMAL, strategy);

		/*
		 * Report to pgstat every 100 blocks (so as not to "spam")
		 */
		if ((b % 100) == 0)
		{
			snprintf(activity, sizeof(activity) - 1, "processing: %s.%s (%s block %d/%d)",
					 get_namespace_name(RelationGetNamespace(reln)), RelationGetRelationName(reln),
					 forkNames[forkNum], b, numblocks);
			pgstat_report_activity(STATE_RUNNING, activity);
		}

		/* Need to get an exclusive lock before we can flag as dirty */
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * Mark the buffer as dirty and force a full page write.  We have to
		 * re-write the page to WAL even if the checksum hasn't changed,
		 * because if there is a replica it might have a slightly different
		 * version of the page with an invalid checksum, caused by unlogged
		 * changes (e.g. hintbits) on the master happening while checksums
		 * were off. This can happen if there was a valid checksum on the page
		 * at one point in the past, so only when checksums are first on, then
		 * off, and then turned on again. Full page writes should only happen
		 * for relations that are actually logged (not unlogged or temp
		 * tables), but we still need to mark their buffers as dirty so the
		 * local file gets updated.
		 */
		START_CRIT_SECTION();
		MarkBufferDirty(buf);
		if (RelationNeedsWAL(reln))
			log_newpage_buffer(buf, false);
		END_CRIT_SECTION();

		UnlockReleaseBuffer(buf);

		/*
		 * This is the only place where we check if we are asked to abort, the
		 * aborting will bubble up from here.
		 */
		if (ChecksumHelperShmem->abort)
			return false;

		/*
		 * Update cost based delay parameters if changed, and then initiate
		 * the cost delay point.
		 */
		if (got_SIGHUP)
		{
			got_SIGHUP = false;
			ProcessConfigFile(PGC_SIGHUP);
			if (checksumhelper_cost_delay >= 0)
				VacuumCostDelay = checksumhelper_cost_delay;
			if (checksumhelper_cost_limit >= 0)
				VacuumCostLimit = checksumhelper_cost_limit;
			VacuumCostActive = (VacuumCostDelay > 0);
		}

		vacuum_delay_point();
	}

	return true;
}

/*
 * ProcessSingleRelationByOid
 *		Process a single relation based on oid.
 *
 * Returns true if successful, and false if *aborted*. On error, an actual error
 * is raised in the lower levels.
 */
static bool
ProcessSingleRelationByOid(Oid relationId, BufferAccessStrategy strategy)
{
	Relation	rel;
	ForkNumber	fnum;
	bool		aborted = false;

	StartTransactionCommand();

	elog(DEBUG2, "Checksumhelper starting to process relation %d", relationId);
	rel = try_relation_open(relationId, AccessShareLock);
	if (rel == NULL)
	{
		/*
		 * Relation no longer exist. We consider this a success, since there
		 * are no pages in it that need checksums, and thus return true.
		 */
		elog(DEBUG1, "Checksumhelper skipping relation %d as it no longer exists", relationId);
		CommitTransactionCommand();
		pgstat_report_activity(STATE_IDLE, NULL);
		return true;
	}
	RelationOpenSmgr(rel);

	for (fnum = 0; fnum <= MAX_FORKNUM; fnum++)
	{
		if (smgrexists(rel->rd_smgr, fnum))
		{
			if (!ProcessSingleRelationFork(rel, fnum, strategy))
			{
				aborted = true;
				break;
			}
		}
	}
	relation_close(rel, AccessShareLock);
	elog(DEBUG2, "Checksumhelper done with relation %d: %s",
		 relationId, (aborted ? "aborted" : "finished"));

	CommitTransactionCommand();

	pgstat_report_activity(STATE_IDLE, NULL);

	return !aborted;
}

/*
 * ProcessDatabase
 *		Enable checksums in a single database.
 *
 * We do this by launching a dynamic background worker into this database, and
 * waiting for it to finish.  We have to do this in a separate worker, since
 * each process can only be connected to one database during its lifetime.
 */
static ChecksumHelperResult
ProcessDatabase(ChecksumHelperDatabase * db)
{
	BackgroundWorker bgw;
	BackgroundWorkerHandle *bgw_handle;
	BgwHandleStatus status;
	pid_t		pid;
	char		activity[NAMEDATALEN + 64];

	ChecksumHelperShmem->success = FAILED;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "ChecksumHelperWorkerMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "checksumhelper worker");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "checksumhelper worker");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = MyProcPid;
	bgw.bgw_main_arg = ObjectIdGetDatum(db->dboid);

	if (!RegisterDynamicBackgroundWorker(&bgw, &bgw_handle))
	{
		ereport(LOG,
				(errmsg("failed to start worker for checksumhelper in \"%s\"",
						db->dbname)));
		return FAILED;
	}

	status = WaitForBackgroundWorkerStartup(bgw_handle, &pid);
	if (status != BGWH_STARTED)
	{
		ereport(LOG,
				(errmsg("failed to wait for worker startup for checksumhelper in \"%s\"",
						db->dbname)));
		return FAILED;
	}

	elog(DEBUG1, "started background worker for checksums in \"%s\"",
		 db->dbname);

	snprintf(activity, sizeof(activity) - 1,
			 "Waiting for worker in database %s (pid %d)", db->dbname, pid);
	pgstat_report_activity(STATE_RUNNING, activity);


	status = WaitForBackgroundWorkerShutdown(bgw_handle);
	if (status != BGWH_STOPPED)
	{
		ereport(LOG,
				(errmsg("failed to wait for worker shutdown for checksumhelper in \"%s\"",
						db->dbname)));
		return FAILED;
	}

	if (ChecksumHelperShmem->success == ABORTED)
		ereport(LOG,
				(errmsg("checksumhelper was aborted during processing in \"%s\"",
						db->dbname)));

	elog(DEBUG1, "background worker for checksums in \"%s\" completed",
		 db->dbname);

	pgstat_report_activity(STATE_IDLE, NULL);

	return ChecksumHelperShmem->success;
}

static void
launcher_exit(int code, Datum arg)
{
	ChecksumHelperShmem->abort = false;
}

static void
launcher_cancel_handler(SIGNAL_ARGS)
{
	ChecksumHelperShmem->abort = true;
}

static void
checksumhelper_sighup(SIGNAL_ARGS)
{
	got_SIGHUP = true;
}

static void
WaitForAllTransactionsToFinish(void)
{
	TransactionId waitforxid;

	LWLockAcquire(XidGenLock, LW_SHARED);
	waitforxid = ShmemVariableCache->nextXid;
	LWLockRelease(XidGenLock);

	while (true)
	{
		TransactionId oldestxid = GetOldestActiveTransactionId();

		elog(DEBUG1, "Waiting for old transactions to finish");
		if (TransactionIdPrecedes(oldestxid, waitforxid))
		{
			char		activity[64];

			/* Oldest running xid is older than us, so wait */
			snprintf(activity, sizeof(activity), "Waiting for current transactions to finish (waiting for %d)", waitforxid);
			pgstat_report_activity(STATE_RUNNING, activity);

			/* Retry every 5 seconds */
			ResetLatch(MyLatch);
			(void) WaitLatch(MyLatch,
							 WL_LATCH_SET | WL_TIMEOUT,
							 5000,
							 WAIT_EVENT_PG_SLEEP);
		}
		else
		{
			pgstat_report_activity(STATE_IDLE, NULL);
			return;
		}
	}
}

void
ChecksumHelperLauncherMain(Datum arg)
{
	List	   *DatabaseList;
	HTAB	   *ProcessedDatabases = NULL;
	List	   *FailedDatabases = NIL;
	ListCell   *lc,
			   *lc2;
	HASHCTL		hash_ctl;
	bool		found_failed = false;

	if (RecoveryInProgress())
	{
		elog(DEBUG1, "not starting checksumhelper launcher, recovery is in progress");
		return;
	}

	/*
	 * If a standby was restarted when in pending state, a background worker
	 * was registered to start. If it's later promoted after the master has
	 * completed enabling checksums, we need to terminate immediately and not
	 * do anything. If the cluster is still in pending state when promoted,
	 * the background worker should start to complete the job.
	 */
	if (DataChecksumsNeedVerifyLocked())
	{
		elog(DEBUG1, "not starting checksumhelper launcher, checksums already enabled");
		return;
	}

	on_shmem_exit(launcher_exit, 0);

	elog(DEBUG1, "checksumhelper launcher started");

	pqsignal(SIGTERM, die);
	pqsignal(SIGINT, launcher_cancel_handler);

	BackgroundWorkerUnblockSignals();

	init_ps_display(pgstat_get_backend_desc(B_CHECKSUMHELPER_LAUNCHER), "", "", "");

	memset(&hash_ctl, 0, sizeof(hash_ctl));
	hash_ctl.keysize = sizeof(Oid);
	hash_ctl.entrysize = sizeof(ChecksumHelperResult);
	ProcessedDatabases = hash_create("Processed databases",
									 64,
									 &hash_ctl,
									 HASH_ELEM);

	/*
	 * Initialize a connection to shared catalogs only.
	 */
	BackgroundWorkerInitializeConnection(NULL, NULL, 0);

	/*
	 * Set up so first run processes shared catalogs, but not once in every
	 * db.
	 */
	ChecksumHelperShmem->process_shared_catalogs = true;

	while (true)
	{
		int			processed_databases;

		/*
		 * Get a list of all databases to process. This may include databases
		 * that were created during our runtime.
		 *
		 * Since a database can be created as a copy of any other database
		 * (which may not have existed in our last run), we have to repeat
		 * this loop until no new databases show up in the list. Since we wait
		 * for all pre-existing transactions finish, this way we can be
		 * certain that there are no databases left without checksums.
		 */

		DatabaseList = BuildDatabaseList();

		/*
		 * If there are no databases at all to checksum, we can exit
		 * immediately as there is no work to do. This probably can never
		 * happen, but just in case.
		 */
		if (DatabaseList == NIL || list_length(DatabaseList) == 0)
			return;

		processed_databases = 0;

		foreach(lc, DatabaseList)
		{
			ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);
			ChecksumHelperResult processing;

			if (hash_search(ProcessedDatabases, (void *) &db->dboid, HASH_FIND, NULL))
				/* This database has already been processed */
				continue;

			processing = ProcessDatabase(db);
			hash_search(ProcessedDatabases, (void *) &db->dboid, HASH_ENTER, NULL);
			processed_databases++;

			if (processing == SUCCESSFUL)
			{
				if (ChecksumHelperShmem->process_shared_catalogs)

					/*
					 * Now that one database has completed shared catalogs, we
					 * don't have to process them again.
					 */
					ChecksumHelperShmem->process_shared_catalogs = false;
			}
			else if (processing == FAILED)
			{
				/*
				 * Put failed databases on the list of failures.
				 */
				FailedDatabases = lappend(FailedDatabases, db);
			}
			else
				/* Abort flag set, so exit the whole process */
				return;
		}

		elog(DEBUG1, "Completed one loop of checksum enabling, %i databases processed", processed_databases);
		if (processed_databases == 0)

			/*
			 * No databases processed in this run of the loop, we have now
			 * finished all databases and no concurrently created ones can
			 * exist.
			 */
			break;
	}

	/*
	 * FailedDatabases now has all databases that failed one way or another.
	 * This can be because they actually failed for some reason, or because
	 * the database was dropped between us getting the database list and
	 * trying to process it. Get a fresh list of databases to detect the
	 * second case where the database was dropped before we had started
	 * processing it. If a database still exists, but enabling checksums
	 * failed then we fail the entire checksumming process and exit with an
	 * error.
	 */
	DatabaseList = BuildDatabaseList();

	foreach(lc, FailedDatabases)
	{
		ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);
		bool		found = false;

		foreach(lc2, DatabaseList)
		{
			ChecksumHelperDatabase *db2 = (ChecksumHelperDatabase *) lfirst(lc2);

			if (db->dboid == db2->dboid)
			{
				found = true;
				ereport(WARNING,
						(errmsg("failed to enable checksums in \"%s\"",
								db->dbname)));
				break;
			}
		}

		if (found)
			found_failed = true;
		else
		{
			ereport(LOG,
					(errmsg("database \"%s\" has been dropped, skipping",
							db->dbname)));
		}
	}

	if (found_failed)
	{
		/* Disable checksums on cluster, because we failed */
		SetDataChecksumsOff();
		ereport(ERROR,
				(errmsg("checksumhelper failed to enable checksums in all databases, aborting")));
	}

	/*
	 * Force a checkpoint to get everything out to disk. XXX: this should
	 * probably not be an IMMEDIATE checkpoint, but leave it there for now for
	 * testing
	 */
	RequestCheckpoint(CHECKPOINT_FORCE | CHECKPOINT_WAIT | CHECKPOINT_IMMEDIATE);

	/*
	 * Everything has been processed, so flag checksums enabled.
	 */
	SetDataChecksumsOn();

	ereport(LOG,
			(errmsg("checksums enabled, checksumhelper launcher shutting down")));
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

	if (!found)
	{
		MemSet(ChecksumHelperShmem, 0, ChecksumHelperShmemSize());
	}
}

/*
 * BuildDatabaseList
 *		Compile a list of all currently available databases in the cluster
 *
 * This creates the list of databases for the checksumhelper workers to add
 * checksums to.
 */
static List *
BuildDatabaseList(void)
{
	List	   *DatabaseList = NIL;
	Relation	rel;
	HeapScanDesc scan;
	HeapTuple	tup;
	MemoryContext ctx = CurrentMemoryContext;
	MemoryContext oldctx;

	StartTransactionCommand();

	rel = heap_open(DatabaseRelationId, AccessShareLock);

	/*
	 * Before we do this, wait for all pending transactions to finish. This
	 * will ensure there are no concurrently running CREATE DATABASE, which
	 * could cause us to miss the creation of a database that was copied
	 * without checksums.
	 */
	WaitForAllTransactionsToFinish();

	scan = heap_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_database pgdb = (Form_pg_database) GETSTRUCT(tup);
		ChecksumHelperDatabase *db;

		oldctx = MemoryContextSwitchTo(ctx);

		db = (ChecksumHelperDatabase *) palloc(sizeof(ChecksumHelperDatabase));

		db->dboid = pgdb->oid;
		db->dbname = pstrdup(NameStr(pgdb->datname));

		DatabaseList = lappend(DatabaseList, db);

		MemoryContextSwitchTo(oldctx);
	}

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	CommitTransactionCommand();

	return DatabaseList;
}

/*
 * BuildRelationList
 *		Compile a list of all relations in the database
 *
 * If shared is true, both shared relations and local ones are returned, else
 * all non-shared relations are returned.
 * Temp tables are not included.
 */
static List *
BuildRelationList(bool include_shared)
{
	List	   *RelationList = NIL;
	Relation	rel;
	HeapScanDesc scan;
	HeapTuple	tup;
	MemoryContext ctx = CurrentMemoryContext;
	MemoryContext oldctx;

	StartTransactionCommand();

	rel = heap_open(RelationRelationId, AccessShareLock);
	scan = heap_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_class pgc = (Form_pg_class) GETSTRUCT(tup);
		ChecksumHelperRelation *relentry;

		if (pgc->relpersistence == 't')
			continue;

		if (pgc->relisshared && !include_shared)
			continue;

		/*
		 * Only include relation types that has local storage.
		 */
		if (pgc->relkind == RELKIND_VIEW ||
			pgc->relkind == RELKIND_COMPOSITE_TYPE ||
			pgc->relkind == RELKIND_FOREIGN_TABLE)
			continue;

		oldctx = MemoryContextSwitchTo(ctx);
		relentry = (ChecksumHelperRelation *) palloc(sizeof(ChecksumHelperRelation));

		relentry->reloid = pgc->oid;
		relentry->relkind = pgc->relkind;

		RelationList = lappend(RelationList, relentry);

		MemoryContextSwitchTo(oldctx);
	}

	heap_endscan(scan);
	heap_close(rel, AccessShareLock);

	CommitTransactionCommand();

	return RelationList;
}

/*
 * Main function for enabling checksums in a single database
 */
void
ChecksumHelperWorkerMain(Datum arg)
{
	Oid			dboid = DatumGetObjectId(arg);
	List	   *RelationList = NIL;
	ListCell   *lc;
	BufferAccessStrategy strategy;
	bool		aborted = false;

	pqsignal(SIGTERM, die);
	pqsignal(SIGHUP, checksumhelper_sighup);

	BackgroundWorkerUnblockSignals();

	init_ps_display(pgstat_get_backend_desc(B_CHECKSUMHELPER_WORKER), "", "", "");

	elog(DEBUG1, "checksum worker starting for database oid %d", dboid);

	BackgroundWorkerInitializeConnectionByOid(dboid, InvalidOid, BGWORKER_BYPASS_ALLOWCONN);

	/*
	 * Enable vacuum cost delay, if any.
	 */
	if (checksumhelper_cost_delay >= 0)
		VacuumCostDelay = checksumhelper_cost_delay;
	if (checksumhelper_cost_limit >= 0)
		VacuumCostLimit = checksumhelper_cost_limit;
	VacuumCostActive = (VacuumCostDelay > 0);
	VacuumCostBalance = 0;
	VacuumPageHit = 0;
	VacuumPageMiss = 0;
	VacuumPageDirty = 0;

	/*
	 * Create and set the vacuum strategy as our buffer strategy.
	 */
	strategy = GetAccessStrategy(BAS_VACUUM);

	RelationList = BuildRelationList(ChecksumHelperShmem->process_shared_catalogs);
	foreach(lc, RelationList)
	{
		ChecksumHelperRelation *rel = (ChecksumHelperRelation *) lfirst(lc);

		if (!ProcessSingleRelationByOid(rel->reloid, strategy))
		{
			aborted = true;
			break;
		}
	}

	if (aborted)
	{
		ChecksumHelperShmem->success = ABORTED;
		elog(DEBUG1, "checksum worker aborted in database oid %d", dboid);
		return;
	}

	ChecksumHelperShmem->success = SUCCESSFUL;
	elog(DEBUG1, "checksum worker completed in database oid %d", dboid);
}
