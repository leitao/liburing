/* SPDX-License-Identifier: MIT */
/*
 * Check that CMD operations on sockets are consistent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <linux/tcp.h>

#include "liburing.h"
#include "helpers.h"

#define USERDATA 0xff0000
#define MSG "foobarbaz"

struct testsocks {
	/* Receive socket */
	int receive;
	/* Send socket */
	int send;
	/* accepted socket */
	int accepted;
};

static struct testsocks create_sockets()
{
	struct sockaddr_in addr;
	struct testsocks retval;
	int32_t val = 1;
	int protocol = 0;
	int err;

	protocol = IPPROTO_TCP;

	retval.receive = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, protocol);
	assert(retval.receive > 0);
	retval.send = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, protocol);
	assert(retval.send > 0);

	err = setsockopt(retval.receive, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
	assert(err != -1);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	assert(!t_bind_ephemeral_port(retval.receive, &addr));

	err = listen(retval.receive, 128);
	assert(err != -1);

	err = connect(retval.send, (struct sockaddr*)&addr, sizeof(addr));
	assert(err != -1);

	retval.accepted = accept(retval.receive, NULL, NULL);
	assert(retval.accepted != -1);

	return retval;
}

static struct io_uring create_ring()
{
	int ring_flags = 0;
	struct io_uring ring;
	int err;

	err = io_uring_queue_init(32, &ring, ring_flags);
	assert(err >= 0);

	return ring;
}

static int setsock_submit_sqe(struct io_uring *ring, int32_t fd,
				 int op, int level, int optname,
				 void *optval, int optlen)
{
	// Create socket
	struct io_uring_sqe* sqe;
	int err;

	assert(fd > 0);

	sqe = io_uring_get_sqe(ring);
	assert(sqe != NULL);

	io_uring_prep_nop(sqe); // zeroing the struct
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->user_data = USERDATA;
	sqe->fd = fd;
	sqe->cmd_op = op;

	/* Populate the cmd section */
	sqe->level = level;
	sqe->optname = optname;
	sqe->optval = (long long unsigned int) optval;
	sqe->optlen = (long long unsigned int) optlen;

	/* Submitting SQE */
	err = io_uring_submit_and_wait(ring, 1);
	if (err != 1)
		fprintf(stderr, "io_uring_submit_and_wait returned %d\n", err);

	return err;
}

static int getsock_submit_sqe(struct io_uring *ring, int32_t fd,
			      int op, int level, int optname,
			      void *optval, int optlen)
{
	// Create socket
	struct io_uring_sqe* sqe;
	int err;

	assert(fd > 0);

	sqe = io_uring_get_sqe(ring);
	assert(sqe != NULL);

	io_uring_prep_nop(sqe); // zeroing the struct
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->user_data = USERDATA;
	sqe->fd = fd;
	sqe->cmd_op = op;

	/* Populate the cmd section */
	sqe->level = level;
	sqe->optname = optname;
	sqe->optval = (long long unsigned int) optval;
	sqe->optlen = optlen;

	/* Submitting SQE */
	err = io_uring_submit_and_wait(ring, 1);
	if (err != 1)
		fprintf(stderr, "io_uring_submit_and_wait returned %d\n", err);

	return err;
}

static int receive_cqe(struct io_uring *ring)
{
	struct io_uring_cqe* cqe;
	int err;

	err = io_uring_wait_cqe(ring, &cqe);
	assert(err ==  0);
	assert(cqe->user_data == USERDATA);
	io_uring_cqe_seen(ring, cqe);

	if (cqe->res != -EOPNOTSUPP && !cqe->res)
		fprintf(stderr, "cqe->res = %d\n", cqe->res);

	/* Return the result of the operation */
	return cqe->res;
}

/*
 * Run getsock operation using (SOL_SOCKET, SO_RCVBUF) using io_uring cmd operation
 * and getsockopt(2) and compare the result
 */
static int run_get_rcvbuf(struct io_uring *ring, struct testsocks *sockstruct)
{
	int sc_val, ur_val;
	unsigned int sc_len = sizeof(sc_val);
	int ur_len = sizeof(ur_val);
	int err;

	/* get through io_uring cmd */
	err = getsock_submit_sqe(ring, sockstruct->accepted, SOCKET_URING_OP_GETSOCKOPT,
					SOL_SOCKET, SO_RCVBUF, &ur_val, ur_len);
	assert(err == 1);

	/* Wait for the CQE */
	ur_len = receive_cqe(ring);
	if (ur_len == -EOPNOTSUPP)
		return T_EXIT_SKIP;
	assert(ur_len >= 0);

	/* Get from the systemcall */
	err = getsockopt(sockstruct->accepted, SOL_SOCKET, SO_RCVBUF, &sc_val, &sc_len);
	assert(err == 0);

	/* Make sure that io_uring operation returns the same value as the systemcall */
	assert(ur_len == sc_len);
	assert(ur_val == sc_val);

	return err;
}

/*
 * Run getsock operation using (SOL_SOCKET, SO_PEERNAME) using io_uring cmd operation
 * and getsockopt(2) and compare the result
 */
static int run_get_peername(struct io_uring *ring, struct testsocks *sockstruct)
{
	struct sockaddr sc_val, ur_val;
	unsigned int sc_len = sizeof(sc_val);
	int ur_len;
	int err;

	/* Get from the systemcall */
	err = getsockopt(sockstruct->accepted, SOL_SOCKET, SO_PEERNAME, &sc_val, &sc_len);
	assert(err == 0);

	/* get through io_uring cmd */
	err = getsock_submit_sqe(ring, sockstruct->accepted, SOCKET_URING_OP_GETSOCKOPT,
				 SOL_SOCKET, SO_PEERNAME, &ur_val, sizeof(ur_val));
	assert(err == 1);

	/* Wait for the CQE */
	ur_len = receive_cqe(ring);
	if (ur_len == -EOPNOTSUPP)
		return T_EXIT_SKIP;
	assert(ur_len >= 0);

	/* Make sure that io_uring operation returns the same value as the systemcall */
	assert(sc_val.sa_family == ur_val.sa_family);
	assert(sc_len == ur_len);

	return T_EXIT_PASS;
}

/*
 * Run getsockopt tests. Basically comparing io_uring output and comparing
 * with the systemcall results
 */
static int run_getsockopt_test(struct io_uring *ring, struct testsocks *sockstruct)
{
	int err;

	fprintf(stderr, "Testing getsockopt SO_PEERNAME\n");
	err = run_get_peername(ring, sockstruct);
	if (err)
		return err;

	fprintf(stderr, "Testing getsockopt SO_RCVBUF\n");
	err = run_get_rcvbuf(ring, sockstruct);

	return err;
}

static int run_set_reuseport(struct io_uring *ring, struct testsocks *sockstruct)
{
	int sval, uval = 0;
	int err;
	unsigned int len;


	/* Setting SO_REUSEPORT */
	err = setsock_submit_sqe(ring, sockstruct->accepted, SOCKET_URING_OP_SETSOCKOPT,
				 SOL_SOCKET, SO_REUSEPORT, &uval, sizeof(uval));
	assert(err == 1);

	err = receive_cqe(ring);
	if (err == -EOPNOTSUPP)
		return T_EXIT_SKIP;

	/* Get from the systemcall */
	err = getsockopt(sockstruct->accepted, SOL_SOCKET, SO_REUSEPORT, &sval, &len);
	assert (err == 0);

	/* Make sure the set using io_uring cmd matches what systemcall returns */
	assert (uval == sval);

	/* Let's do the oposite now, and set SO_REUSEPORT*/
	uval = 1;

	/* set through io_uring cmd */
	err = setsock_submit_sqe(ring, sockstruct->accepted, SOCKET_URING_OP_SETSOCKOPT,
				 SOL_SOCKET, SO_REUSEPORT, &uval, sizeof(uval));
	assert(err == 1);
	/* Wait for the CQE */
	err = receive_cqe(ring);
	if (err == -EOPNOTSUPP)
		return T_EXIT_SKIP;
	assert(err == 0);

	err = getsockopt(sockstruct->accepted, SOL_SOCKET, SO_REUSEPORT, &sval, &len);
	assert(err == 0);

	/* Make sure the set using io_uring cmd matches what systemcall returns */
	assert (uval == sval);

	return T_EXIT_PASS;
}

/* Test setsockopt() for IPPROTO_TCP */
static int run_set_fastopen(struct io_uring *ring, struct testsocks *sockstruct)
{
	int sval, uval = 1;
	int err;
	unsigned int len = sizeof(uval);
	int level = IPPROTO_TCP;
	int optname = TCP_FASTOPEN;

	/* Setting SO_FASTOPEN */
	err = setsock_submit_sqe(ring, sockstruct->receive, SOCKET_URING_OP_SETSOCKOPT,
				 level, optname, &uval, sizeof(uval));
	assert(err == 1);

	err = receive_cqe(ring);
	if (err == -EOPNOTSUPP)
		return T_EXIT_SKIP;
	assert (err == 0);

	/* Get the configuration from the systemcall, to make sure it was set */
	err = getsockopt(sockstruct->receive, level, optname, &sval, &len);
	assert (err == 0);

	/* Make sure the set using io_uring cmd matches what systemcall returns */
	assert (uval == sval);

	/* Let's do the oposite now */
	uval = 9;

	/* set through io_uring cmd */
	err = setsock_submit_sqe(ring, sockstruct->receive, SOCKET_URING_OP_SETSOCKOPT,
				 level, optname, &uval, sizeof(uval));
	assert(err == 1);

	/* Wait for the CQE */
	err = receive_cqe(ring);
	if (err == -EOPNOTSUPP)
		return T_EXIT_SKIP;
	fprintf(stderr, "err = %d\n", err);
	assert(err == 0);

	err = getsockopt(sockstruct->receive, level, optname, &sval, &len);
	assert(err == 0);

	/* Make sure the set using io_uring cmd matches what systemcall returns */
	assert (uval == sval);

	return T_EXIT_PASS;
}

/* Test setsockopt() for SOL_SOCKET */
static int run_setsockopt_test(struct io_uring *ring, struct testsocks *sockstruct)
{
	int err;

	fprintf(stderr, "Testing set SOL_SOCKET/SO_REUSEPORT\n");
	err = run_set_reuseport(ring, sockstruct);
	if (err)
		return err;

	fprintf(stderr, "Testing set IPPROTO_TCP/TCP_FASTOPEN\n");
	err = run_set_fastopen(ring, sockstruct);

	return err;
}

/* Send data throughts the sockets */
void send_data(struct testsocks *s)
{
	int written_bytes;
	/* Send data sing the sockstruct->send */
	written_bytes = write(s->send, MSG, strlen(MSG));
	assert(written_bytes == strlen(MSG));
}

int main(int argc, char *argv[])
{
	struct testsocks sockstruct;
	struct io_uring ring;
	int err;

	if (argc > 1)
		return 0;

	/* Simply io_uring ring creation */
	ring = create_ring();

	/* Create three sockets */
	sockstruct = create_sockets();

	send_data(&sockstruct);

	err = run_getsockopt_test(&ring, &sockstruct);
	if (err) {
		if (err == T_EXIT_SKIP)
			fprintf(stderr, "Skipping tests. -ENOTSUP returned\n");
		fprintf(stderr, "Failed ot run test: %d\n", err);
		return err;
	}

	err = run_setsockopt_test(&ring, &sockstruct);
	if (err) {
		if (err == T_EXIT_SKIP)
			fprintf(stderr, "Skipping tests. -ENOTSUP returned\n");
		fprintf(stderr, "Failed ot run test: %d\n", err);
		return err;
	}

	io_uring_queue_exit(&ring);
	return err;
}
