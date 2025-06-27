// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/errqueue.h>
#include "icmp_send_unreach.skel.h"

#define TIMEOUT_MS 1000
#define SRV_PORT 54321

#define ICMP_DEST_UNREACH 3

#define ICMP_FRAG_NEEDED 4
#define NR_ICMP_UNREACH 15

static void read_icmp_errqueue(int sockfd, int expected_code)
{
	ssize_t n;
	struct sock_extended_err *sock_err;
	char ctrl_buf[512];
	struct msghdr msg = {
		.msg_control = ctrl_buf,
		.msg_controllen = sizeof(ctrl_buf),
	};

	n = recvmsg(sockfd, &msg, MSG_ERRQUEUE);
	if (!ASSERT_GE(n, 0, "recvmsg_errqueue"))
		return;

	struct cmsghdr *cm;
	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (!ASSERT_EQ(cm->cmsg_level, IPPROTO_IP, "cmsg_type") ||
		    !ASSERT_EQ(cm->cmsg_type, IP_RECVERR, "cmsg_level"))
			continue;

		sock_err = (struct sock_extended_err *)CMSG_DATA(cm);

		if (!ASSERT_EQ(sock_err->ee_origin, SO_EE_ORIGIN_ICMP,
			       "sock_err_origin_icmp"))
			return;
		if (!ASSERT_EQ(sock_err->ee_type, ICMP_DEST_UNREACH,
			       "sock_err_type_dest_unreach"))
			return;
		ASSERT_EQ(sock_err->ee_code, expected_code, "sock_err_code");
	}
}

void test_icmp_send_unreach_kfunc(void)
{
	struct icmp_send_unreach *skel;
	int cgroup_fd, client_fd, srv_fd;
	int *code;

	skel = icmp_send_unreach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	cgroup_fd = test__join_cgroup("/icmp_send_unreach_cgroup");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto cleanup;

	skel->links.egress =
		bpf_program__attach_cgroup(skel->progs.egress, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.egress, "prog_attach_cgroup"))
		goto cleanup;

	code = &skel->bss->unreach_code;

	// Let the packet pass to read the ICMP message from the erreur queue
	skel->bss->decision = SK_PASS;

	for (*code = 0; *code <= NR_ICMP_UNREACH; (*code)++) {
		if (*code == ICMP_FRAG_NEEDED)
			continue;

		srv_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1",
				      SRV_PORT, TIMEOUT_MS);
		if (!ASSERT_GE(srv_fd, 0, "start_server"))
			goto for_cleanup;

		client_fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_GE(client_fd, 0, "client_socket");

		client_fd = connect_to_fd(srv_fd, 0);
		if (!ASSERT_GE(client_fd, 0, "client_connect"))
			goto for_cleanup;

		read_icmp_errqueue(client_fd, *code);

for_cleanup:
		if (client_fd >= 0)
			close(client_fd);
		if (srv_fd >= 0)
			close(srv_fd);
	}

	skel->bss->decision = SK_DROP;

	for (*code = 0; *code <= NR_ICMP_UNREACH; (*code)++) {
		if (*code == ICMP_FRAG_NEEDED)
			continue;

		srv_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1",
				      SRV_PORT, TIMEOUT_MS);
		if (!ASSERT_GE(srv_fd, 0, "start_server"))
			goto for_cleanup2;

		client_fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_GE(client_fd, 0, "client_socket");

		client_fd = connect_to_fd(srv_fd, 0);
		if (!ASSERT_GE(client_fd, 0, "client_connect"))
			goto for_cleanup2;

		read_icmp_errqueue(client_fd, *code);

for_cleanup2:
		if (client_fd >= 0)
			close(client_fd);
		if (srv_fd >= 0)
			close(srv_fd);
	}

cleanup:
	icmp_send_unreach__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}
