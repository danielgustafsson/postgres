/*-------------------------------------------------------------------------
 *
 * checksumhelper.h
 *	  header file for checksum helper deamon
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/postmaster/checksumhelper.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CHECKSUMHELPER_H
#define CHECKSUMHELPER_H

/* Shared memory */
extern Size ChecksumHelperShmemSize(void);
extern void ChecksumHelperShmemInit(void);

/* Start the background processes for enabling checksums */
bool StartChecksumHelperLauncher(void);

/* Shutdown the background processes, if any */
void ShutdownChecksumHelperIfRunning(void);

/* Background worker entrypoints */
void ChecksumHelperLauncherMain(Datum arg);
void ChecksumHelperWorkerMain(Datum arg);

#endif							/* CHECKSUMHELPER_H */
