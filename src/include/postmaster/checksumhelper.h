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

/* Status functions */
extern bool IsChecksumHelperLauncherProcess(void);
extern bool IsChecksumHelperWorkerProcess(void);

/* Shared memory */
extern Size ChecksumHelperShmemSize(void);
extern void ChecksumHelperShmemInit(void);

/* Called from the postmaster */
int StartChecksumHelperLauncher(void);

#ifdef EXEC_BACKEND
extern void ChecksumHelperLauncherMain(int argc, char **argv);
#endif

#endif							/* CHECKSUMHELPER_H */
