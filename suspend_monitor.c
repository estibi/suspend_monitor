#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <procfs.h>
#include <utmpx.h>
#include <time.h>
#include <sys/uadmin.h>

/*
 * gcc -Wall -m64 -o suspend_monitor suspend_monitor.c
 */

#define	SLEEP_TIME 60
#define	LOOP_COUNTER 15
#define	PIDS_LIMIT 3000
#define	PROCDIR "/proc"

#define	process_to_watch "afpd"


struct pids_struct {
	int *pids[PIDS_LIMIT];
	int amount;
};

static int get_pr_flags(char *);

static void
pgrep(struct pids_struct *all_pids, struct pids_struct *pgrep_pids, char *name)
{
	char fname[PATH_MAX];
	int procfd;
	psinfo_t psinfo;
	int i, found = 0;

	for (i = 0; i < all_pids->amount; i++) {
		snprintf(fname,
			sizeof (fname),
			"%s/%d/%s",
			PROCDIR,
			(int)(intptr_t)all_pids->pids[i],
			"psinfo");
		procfd = open(fname, 'r');
		if (read(procfd, &psinfo, sizeof (psinfo)) == -1) {
			printf("ERROR: %s\n", strerror(errno));
		}
		if ((strcmp(psinfo.pr_fname, name) == 0)) {
			/* found a process */
			pgrep_pids->pids[found] = all_pids->pids[i];
			found++;
		}
		(void) close(procfd);
	}
	pgrep_pids->amount = found;
	printf("found %d pids with a name %s\n", pgrep_pids->amount, name);
	printf("\n");
}

static bool
are_active_threads(struct pids_struct *pids)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	char fname[PATH_MAX];
	int i, flags;
	int **pp;
	char *tmpp = NULL;
	bool is_active = false;

	printf("LWP status:\n");
	for (i = 0; i < pids->amount; i++) {
		pp = pids->pids;
		snprintf(fname,
			sizeof (fname),
			"%s/%d/lwp",
			PROCDIR,
			(int)(intptr_t)pp[i]);
		/* tmpp = end of string: /proc/20392/lwp */
		tmpp = &fname[strnlen(fname, sizeof (fname))];

		/* open lwp directory */
		dirp = opendir(fname);
		if (!dirp) {
			printf("ERROR: Can't open '%s':\n", fname);
			printf("%s\n", strerror(errno));
			return (false);
		}

		/* reading lwp directory */
		while ((ent = readdir(dirp)) != NULL) {
			if (ent->d_name[0] == '.')
				continue; /* skip hidden files */
			snprintf(tmpp,
				sizeof (fname) - strnlen(fname, sizeof (fname)),
				"/%s/lwpstatus",
				ent->d_name);

			flags = get_pr_flags(fname);

			if (!(flags & PR_ASLEEP)) {
				printf("%-30s status: 0x%x - active\n",
					fname,
					flags);
					is_active = true;
					break;
			}
		}
		(void) closedir(dirp);
		if (is_active) break;
	}
	printf("\n");
	return (is_active);
}

static int
get_pr_flags(char * lwpname)
{
	int flags, lwpfd;
	lwpstatus_t status;

	lwpfd = open(lwpname, O_RDONLY);

	if (read(lwpfd, &status, sizeof (status)) == -1) {
		printf("ERROR for %s - %s\n", lwpname, strerror(errno));
		flags = -1;
	} else {
		flags = status.pr_flags;
	}

	(void) close(lwpfd);
	return (flags);
}


static void
show_pids(struct pids_struct *pids)
{
	int i;
	printf("amount: %d\n", pids->amount);

	for (i = 0; i < pids->amount; i++) {
		printf("PID: %d\n", (int)(intptr_t)pids->pids[i]);
	}
}

static void
get_pids(struct pids_struct *all_pids)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	int index = 0;
	all_pids->amount = 0;

	dirp = opendir(PROCDIR);
	if (!dirp) {
		printf("ERROR: Can't open '%s':\n", PROCDIR);
		printf("%s\n", strerror(errno));
		return;
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue; /* skip . and .. */
		all_pids->pids[index] = (int *)(intptr_t)atoi(ent->d_name);
		index++;
	}
	(void) closedir(dirp);
	all_pids->amount = index;
}

static void
suspend_machine()
{
	int cmd = A_FREEZE;
	int fcn = AD_SUSPEND_TO_RAM;
	uintptr_t mdep = NULL;
	int ret;

	printf("Suspending machine..\n");
	ret = uadmin(cmd, fcn, mdep);
	if (ret == -1) {
		printf("ERROR: Can't suspend machine:\n");
		printf("%s\n", strerror(errno));
	}
}

static void
print_utmpx(struct utmpx *up)
{
	time_t t = (time_t)up->ut_tv.tv_sec;
	struct tm *tmp = localtime(&t);

	printf("%-20s%s\n", "UTMPX ut_user:", up->ut_user);
	printf("%-20s%s\n", "UTMPX ut_line:", up->ut_line);
	printf("%-20s%s", "UTMPX ut_tv.tv_sec:", asctime(tmp));
	printf("%-20s%s\n", "UTMPX ut_host:", up->ut_host);
	printf("\n");
}

static bool
are_active_sessions()
{
	struct utmpx *utmpxp = NULL;
	bool is_active = false;

	printf("Checking for active user sessions..\n");

	for (;;) {
		utmpxp = getutxent();
		if (utmpxp == NULL)
			break;

		if (utmpxp->ut_type != USER_PROCESS)
			continue;

		// show active user session
		print_utmpx(utmpxp);
		is_active = true;
	}

	endutxent();
	return (is_active);
}


static void
main_loop()
{
	struct pids_struct all_pids, pgrep_pids;
	bool is_active_proc = true;
	bool is_active_session = true;
	int counter = LOOP_COUNTER;

	for (;;) {
		printf("Loop counter: %d\n", counter);
		if (counter == 0) {
			printf("Checking %s threads.\n", process_to_watch);
			get_pids(&all_pids);
			pgrep(&all_pids, &pgrep_pids, process_to_watch);

			printf("Found selected PIDs:\n");
			show_pids(&pgrep_pids);
			printf("\n");

			// active processes
			is_active_proc = are_active_threads(&pgrep_pids);
			if (is_active_proc) {
				printf("Active thread found.\n");
			}

			// active ssh/console sessions
			is_active_session = are_active_sessions();
			if (is_active_session) {
				printf("Active session found.\n");
			}

			if (!(is_active_proc || is_active_session)) {
				suspend_machine();
				counter = LOOP_COUNTER;
			}
		} else {
			counter--;
		}

		printf("Sleeping for: %d sec\n", SLEEP_TIME);
		printf("\n");
		sleep(SLEEP_TIME);
	}
}

int
main(int argc, char **argv) {
	main_loop();
	return (0);
}
