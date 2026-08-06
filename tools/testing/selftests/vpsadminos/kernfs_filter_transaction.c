// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define POLICY_MAX_BYTES (256 * 1024)

static int read_file(const char *path, char **bufp, size_t *lenp)
{
	char *buf;
	ssize_t n;
	size_t len = 0;
	int fd;

	buf = malloc(POLICY_MAX_BYTES + 1);
	if (!buf) {
		perror("malloc");
		return -1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		free(buf);
		return -1;
	}

	while (len < POLICY_MAX_BYTES + 1) {
		n = read(fd, buf + len, POLICY_MAX_BYTES + 1 - len);
		if (n < 0) {
			perror("read");
			close(fd);
			free(buf);
			return -1;
		}
		if (!n)
			break;
		len += n;
	}

	if (close(fd)) {
		perror("close");
		free(buf);
		return -1;
	}
	if (len > POLICY_MAX_BYTES) {
		fprintf(stderr, "%s exceeds the policy size limit\n", path);
		free(buf);
		return -1;
	}

	buf[len] = '\0';
	*bufp = buf;
	*lenp = len;
	return 0;
}

static int read_generation(const char *stats, unsigned long long *generation)
{
	char line[256];
	FILE *f;

	f = fopen(stats, "re");
	if (!f) {
		perror(stats);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "generation %llu", generation) == 1) {
			if (fclose(f)) {
				perror("fclose");
				return -1;
			}
			return 0;
		}
	}

	fprintf(stderr, "%s has no generation field\n", stats);
	fclose(f);
	return -1;
}

static int expect_generation(const char *stats, unsigned long long expected,
			     const char *label)
{
	unsigned long long generation;

	if (read_generation(stats, &generation))
		return -1;
	if (generation != expected) {
		fprintf(stderr, "%s: expected generation %llu, got %llu\n",
			label, expected, generation);
		return -1;
	}
	return 0;
}

static int expect_active(const char *active, const char *expected,
			 size_t expected_len, const char *label)
{
	char *actual;
	size_t actual_len;
	int ret = -1;

	if (read_file(active, &actual, &actual_len))
		return -1;
	if (actual_len != expected_len || memcmp(actual, expected, expected_len)) {
		fprintf(stderr, "%s: active policy changed unexpectedly\n", label);
		goto out;
	}

	ret = 0;
out:
	free(actual);
	return ret;
}

static int open_replace(const char *replace)
{
	int fd = open(replace, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		perror(replace);
	return fd;
}

static int expect_failed_write(int fd, const void *buf, size_t len,
			       int expected_errno, const char *label)
{
	ssize_t n;

	errno = 0;
	n = write(fd, buf, len);
	if (n != -1 || errno != expected_errno) {
		fprintf(stderr,
			"%s: expected write errno %d, got return %zd errno %d\n",
			label, expected_errno, n, errno);
		return -1;
	}
	return 0;
}

static int close_checked(int fd, const char *label)
{
	if (!close(fd))
		return 0;

	fprintf(stderr, "%s: close failed: %s\n", label, strerror(errno));
	return -1;
}

static int install_policy(const char *replace, const char *policy)
{
	char *buf;
	size_t len;
	ssize_t n;
	int fd;
	int ret = -1;

	if (read_file(policy, &buf, &len) || !len)
		return -1;

	fd = open_replace(replace);
	if (fd < 0)
		goto out;
	n = write(fd, buf, len);
	if (n != (ssize_t)len) {
		fprintf(stderr, "install: write returned %zd: %s\n",
			n, n < 0 ? strerror(errno) : "short write");
		close(fd);
		goto out;
	}
	if (close_checked(fd, "install"))
		goto out;

	ret = 0;
out:
	free(buf);
	return ret;
}

int main(int argc, char **argv)
{
	static const char malformed[] = "this is not a policy\n";
	static const char partial_header[] = "version 1\n";
	static const char partial_scope[] = "scope noninit-userns\n";
	const char *replace;
	const char *active;
	const char *stats;
	char *original = NULL;
	char *valid = NULL;
	size_t original_len;
	size_t valid_len;
	unsigned long long generation;
	ssize_t n;
	int fd = -1;
	int ret = 1;

	if (argc == 4 && !strcmp(argv[1], "install"))
		return install_policy(argv[2], argv[3]) ? 1 : 0;

	if (argc != 5) {
		fprintf(stderr,
			"usage: %s REPLACE ACTIVE STATS VALID_POLICY\n"
			"       %s install REPLACE POLICY\n",
			argv[0], argv[0]);
		return 1;
	}

	replace = argv[1];
	active = argv[2];
	stats = argv[3];
	if (read_file(active, &original, &original_len) ||
	    read_file(argv[4], &valid, &valid_len) || !valid_len ||
	    read_generation(stats, &generation))
		goto out;

	fd = open_replace(replace);
	if (fd < 0 || close_checked(fd, "empty transaction") ||
	    expect_generation(stats, generation, "empty transaction") ||
	    expect_active(active, original, original_len, "empty transaction"))
		goto out;
	fd = -1;

	fd = open_replace(replace);
	if (fd < 0 ||
	    expect_failed_write(fd, malformed, sizeof(malformed) - 1, EINVAL,
				"malformed transaction") ||
	    expect_failed_write(fd, valid, valid_len, EINVAL,
				"valid write after malformed transaction") ||
	    close_checked(fd, "malformed transaction") ||
	    expect_generation(stats, generation, "malformed transaction") ||
	    expect_active(active, original, original_len, "malformed transaction"))
		goto out;
	fd = -1;

	fd = open_replace(replace);
	if (fd < 0 ||
	    expect_failed_write(fd, partial_header, sizeof(partial_header) - 1,
				EINVAL, "partial header") ||
	    expect_failed_write(fd, partial_scope, sizeof(partial_scope) - 1,
				EINVAL, "partial continuation") ||
	    close_checked(fd, "partial transaction") ||
	    expect_generation(stats, generation, "partial transaction") ||
	    expect_active(active, original, original_len, "partial transaction"))
		goto out;
	fd = -1;

	fd = open_replace(replace);
	if (fd < 0 || expect_failed_write(fd, "", 0, EINVAL, "zero-length transaction") ||
	    close_checked(fd, "zero-length transaction") ||
	    expect_generation(stats, generation, "zero-length transaction") ||
	    expect_active(active, original, original_len, "zero-length transaction"))
		goto out;
	fd = -1;

	fd = open_replace(replace);
	if (fd < 0)
		goto out;
	n = write(fd, valid, valid_len);
	if (n != (ssize_t)valid_len) {
		fprintf(stderr, "complete transaction: write returned %zd: %s\n",
			n, n < 0 ? strerror(errno) : "short write");
		goto out;
	}
	if (expect_failed_write(fd, valid, valid_len, EINVAL, "second write") ||
	    close_checked(fd, "complete transaction"))
		goto out;
	fd = -1;

	if (expect_generation(stats, generation + 1, "complete transaction") ||
	    expect_active(active, valid, valid_len, "complete transaction"))
		goto out;

	printf("ok: kernfs-filter replacement is synchronous and transactional\n");
	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(valid);
	free(original);
	return ret;
}
