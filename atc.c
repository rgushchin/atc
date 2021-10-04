// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "atc.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct atc_bpf *skel;
	int pid = 0, tgid = 0, child = 0, allret = 0, keep = 0, reset = 0;
	unsigned long cgid = 0;
	unsigned long ts = 100000000; // 100 milliseconds
	char msg[128] = {0};
	int err, i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "help") || !strcmp(argv[i], "--help") ||
		    !strcmp(argv[i], "-help") || !strcmp(argv[i], "-h") ||
		    !strcmp(argv[i], "?"))
			goto usage;

		if (!strcmp(argv[i], "cmd") || !strcmp(argv[i], "-c")) {
			if (i++ == argc)
				goto usage;
			child = fork();
			switch (child) {
			case -1:
				fprintf(stderr, "Failed to fork\n");
				return -1;
			case 0:
				sleep(3);
				printf("----------------------------------------\n");
				return execvp(argv[i], &argv[i]);
			default:
				pid = child;
			}
			snprintf(msg, sizeof(msg), "prioritize task(s) with pid %d", pid);
		} else if (!strcmp(argv[i], "pid") || !strcmp(argv[i], "-p")) {
			if (i++ == argc)
				goto usage;
			pid = atoi(argv[i]);
			snprintf(msg, sizeof(msg), "prioritize task(s) with pid %d", pid);
		} else if (!strcmp(argv[i], "tgid") || !strcmp(argv[i], "-t")) {
			if (i++ == argc)
				goto usage;
			tgid = atoi(argv[i]);
			snprintf(msg, sizeof(msg), "prioritize task with tgid %d", tgid);
		} else if (!strcmp(argv[i], "ts") || !strcmp(argv[i], "-s")) {
			if (i++ == argc)
				goto usage;
			ts = atol(argv[i]) * 1000000;

			if (ts > 1000000000)
				ts = 1000000000;
			if (ts < 1000000)
				ts = 1000000;
		} else if (!strcmp(argv[i], "all") || !strcmp(argv[i], "-a")) {
			if (i++ == argc)
				goto usage;
			allret = atoi(argv[i]);
			snprintf(msg, sizeof(msg), "suppress all non-voluntary context switches");
		} else if (!strcmp(argv[i], "cgroup") || !strcmp(argv[i], "-g")) {
			if (i++ == argc)
				goto usage;
			if (isdigit(argv[i][0])) {
				cgid = atol(argv[i]);
			} else {
				struct stat st;

				if (stat(argv[i], &st) < 0) {
					fprintf(stderr, "Failed to determine a cgroup id\n");
					return -1;
				}

				cgid = st.st_ino;
			}
			snprintf(msg, sizeof(msg), "prioritize tasks within cgroup with id %lu", cgid);
		} else if (!strcmp(argv[i], "keep") || !strcmp(argv[i], "-k")) {
			keep = 1;
		} else if (!strcmp(argv[i], "reset") || !strcmp(argv[i], "-r")) {
			reset = 1;
		} else {
			goto usage;
		}
	}

	if (reset) {
		err = system("rm -f /sys/fs/bpf/sched_*");
		if (err)
			return -err;
	}

	if (!pid && !tgid && !cgid && !allret) {
		if (reset)
			return 0;
		goto usage;
	}

	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();

	skel = atc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->tgidpid = (unsigned long)tgid << 32 | pid;
	skel->bss->cgid = cgid;
	skel->bss->allret = allret;
	skel->bss->max_exec_slice = ts;

	err = atc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = atc_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("%s\n", msg);

	if (keep > 0) {
		int i;

		for (i = 0; i < skel->skeleton->prog_cnt; i++) {
			char buf[128] = {0};

			snprintf(buf, sizeof(buf), "/sys/fs/bpf/sched_%s",
				 skel->skeleton->progs[i].name);

			err= bpf_link__pin(*skel->skeleton->progs[i].link, buf);
			if (err)
				goto cleanup;
		}

		return 0;
	} else {
		for (;;)
			sleep(1);
	}

cleanup:
	atc_bpf__destroy(skel);
	if (child)
		wait(NULL);
	return -err;

usage:
	fprintf(stderr,
		"Usage: %s\n"
		"\tcmd, -c <cmd args>: execute command <cmd> and prioritize it\n"
		"\tpid, -p <pid>: prioritize task with pid <pid>\n"
		"\ttgid, -t <tgid>: prioritize task(s) with tgid <tgid>\n"
		"\tcgroup, -g <path/cgid>: prioritize task(s) within cgroup with <path/cgid>\n"
		"\tall, -a <ret>: suppress all non-voluntary context switches\n"
		"\tts, -s <timeslice>: max timeslice in milliseconds [1..1000]\n"
		"\tkeep, -k: keep programs loaded and attached using bpffs\n"
		"\treset, -r: delete all sched_ programs from bpffs\n"
		"\thelp, -h, -?: print this message\n", argv[0]);
	return 1;
}
