#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/un.h>

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"


void send_option(int fd, enum uftrace_dopt opt) {
    if (write(fd, &opt, sizeof(enum uftrace_dopt)) == -1)
            pr_err("error sending option type");
}

int command_client(int argc, char *argv[], struct opts *opts) {
    int sfd;        /* Socket file descriptor, to communicate with the daemon */
    uid_t uid;
    char *channel = NULL;
    char command[MCOUNT_DOPT_SIZE];
    struct sockaddr_un addr;

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1)
        pr_err("error opening socket");

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;

    uid = getuid();
    xasprintf(&channel, "/var/run/user/%d/uftrace/%d.socket", uid, opts->pid);
    strncpy(addr.sun_path, channel,
            sizeof(addr.sun_path) - 1);

    if (connect(sfd, (struct sockaddr *) &addr,
                sizeof(struct sockaddr_un)) == -1)
        pr_err("error connecting to socket");

    if (opts->disabled) {
        send_option(sfd, UFTRACE_DOPT_DISABLED);
        if (write(sfd, &opts->disabled, sizeof(bool)) == -1)
            pr_err("error sending options");
    }

    if (opts->patt_type != PATT_REGEX) {
        send_option(sfd, UFTRACE_DOPT_PATT_TYPE);
        pr_dbg3("changing pattern type\n");

        if (write(sfd, &opts->patt_type,
                  sizeof(enum uftrace_pattern_type)) == -1)
            pr_err("error sending options");
    }

    if (opts->depth != -1) {
        send_option(sfd, UFTRACE_DOPT_DEPTH);
        pr_dbg3("changing depth\n");

        if (write(sfd, &opts->depth, sizeof(int)) == -1)
            pr_err("error sending options");
    }

    if (opts->patch) {
        send_option(sfd, UFTRACE_DOPT_PATCH);
        pr_dbg3("changing patch options\n");

        strcpy(command, opts->patch);
        if (write(sfd, &command, MCOUNT_DOPT_SIZE) == -1)
            pr_err("error sending options");
    }

    if (opts->filter) {
        char *filter_str = uftrace_clear_kernel(opts->filter);

        pr_dbg3("changing filter options\n");
        if (filter_str) {
            send_option(sfd, UFTRACE_DOPT_FILTER);

            if (write(sfd, filter_str, MCOUNT_DOPT_SIZE) == -1)
                pr_err("error sending options");

            free(filter_str);
        }
    }

    if (opts->caller) {
        pr_dbg3("changing caller filter options\n");
        send_option(sfd, UFTRACE_DOPT_CALLER_FILTER);

        strcpy(command, opts->caller);
        if (write(sfd, &command, MCOUNT_DOPT_SIZE) == -1)
            pr_err("error sending options");
    }

    if (opts->trigger) {
        pr_dbg3("changing trigger options\n");
        send_option(sfd, UFTRACE_DOPT_TRIGGER);

        strcpy(command, opts->trigger);
        if (write(sfd, &command, MCOUNT_DOPT_SIZE) == -1)
            pr_err("error sending options");
    }

    if (opts->args) {
        pr_dbg3("changing argument options\n");
        send_option(sfd, UFTRACE_DOPT_ARGUMENT);

        strcpy(command, opts->args);
        if (write(sfd, &command, MCOUNT_DOPT_SIZE) == -1)
            pr_err("error sending options");
    }

    if (opts->retval) {
        pr_dbg3("changing retval options\n");
        send_option(sfd, UFTRACE_DOPT_RETVAL);

        strcpy(command, opts->retval);
        if (write(sfd, &command, MCOUNT_DOPT_SIZE) == -1)
            pr_err("error sending options");
    }

    if (opts->threshold) {
        pr_dbg3("changing time filter value\n");
        send_option(sfd, UFTRACE_DOPT_THRESHOLD);

        if (write(sfd, &opts->threshold, sizeof(typeof (opts->threshold))) == -1)
            pr_err("error sending options");
    }

    if (opts->watch) {
        pr_dbg3("changing watchpoints options\n");
        send_option(sfd, UFTRACE_DOPT_WATCH);

        strcpy(command, opts->watch);
        if (write(sfd, &command, MCOUNT_DOPT_SIZE) == -1)
            pr_err("error sending options");
    }

    if (opts->kill) {
        send_option(sfd, UFTRACE_DOPT_KILL);
    }
    else {
        send_option(sfd, UFTRACE_DOPT_CLOSE);
    }

    close(sfd);

    free(channel);

    return 0;
}

