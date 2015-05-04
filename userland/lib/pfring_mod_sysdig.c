/*
 *
 * (C) 2014 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_mod_sysdig.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/* **************************************************** */

static const struct sysdig_event_info sysdig_events[SYSDIG_EVENT_MAX] = {
  /* SYSDIG_GENERIC_E */ { SYSDIG_ENTER, "syscall", 2, { { "ID", SYSDIG_TYPE_SYSCALLID, SYSDIG_PRINT_FORMAT_DEC}, { "nativeID", SYSDIG_TYPE_UINT16, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_GENERIC_X */ { SYSDIG_EXIT, "syscall", 1, { { "ID", SYSDIG_TYPE_SYSCALLID, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_OPEN_E */ { SYSDIG_ENTER, "open", 0},
  /* SYSDIG_SYSCALL_OPEN_X */ { SYSDIG_EXIT, "open", 4, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "name", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX }, { "mode", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_CLOSE_E */ { SYSDIG_ENTER, "close", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_CLOSE_X */ { SYSDIG_EXIT, "close", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_READ_E */ { SYSDIG_ENTER, "read", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_READ_X */ { SYSDIG_EXIT, "read", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_WRITE_E */ { SYSDIG_ENTER, "write", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_WRITE_X */ { SYSDIG_EXIT, "write", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_BRK_1_E */ { SYSDIG_ENTER, "brk", 1, { { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_BRK_1_X */ { SYSDIG_EXIT, "brk", 1, { { "res", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_EXECVE_8_E */ { SYSDIG_ENTER, "execve", 0},
  /* SYSDIG_SYSCALL_EXECVE_8_X */ { SYSDIG_EXIT, "execve", 8, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "exe", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "args", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA}, { "tid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "ptid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "cwd", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "fdlimit", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_CLONE_11_E */ { SYSDIG_ENTER, "clone", 0},
  /* SYSDIG_CLONE_11_X */ { SYSDIG_EXIT, "clone", 11, { { "res", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "exe", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "args", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA}, { "tid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "ptid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "cwd", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "fdlimit", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "uid", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "gid", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_PROCEXIT_E */ { SYSDIG_ENTER, "procexit", 0},
  /* SYSDIG_NA1 */ { SYSDIG_ENTER, "NA1", 0},
  /* SYSDIG_SOCKET_SOCKET_E */ { SYSDIG_ENTER, "socket", 3, { { "domain", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_DEC }, { "type", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "proto", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_SOCKET_X */ { SYSDIG_EXIT, "socket", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_BIND_E */ { SYSDIG_ENTER, "bind", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_BIND_X */ { SYSDIG_EXIT, "bind", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "addr", SYSDIG_TYPE_SOCKADDR, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_CONNECT_E */ { SYSDIG_ENTER, "connect", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_CONNECT_X */ { SYSDIG_EXIT, "connect", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_LISTEN_E */ { SYSDIG_ENTER, "listen", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "backlog", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_LISTEN_X */ { SYSDIG_EXIT, "listen", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_ACCESYSDIG_TYPE_E */ { SYSDIG_ENTER, "accept", 0},
  /* SYSDIG_SOCKET_ACCESYSDIG_TYPE_X */ { SYSDIG_EXIT, "accept", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA}, { "queuepct", SYSDIG_TYPE_UINT8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SEND_E */ { SYSDIG_ENTER, "send", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SEND_X */ { SYSDIG_EXIT, "send", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_SENDTO_E */ { SYSDIG_ENTER, "sendto", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_SENDTO_X */ { SYSDIG_EXIT, "sendto", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_RECV_E */ { SYSDIG_ENTER, "recv", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_RECV_X */ { SYSDIG_EXIT, "recv", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_RECVFROM_E */ { SYSDIG_ENTER, "recvfrom", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_RECVFROM_X */ { SYSDIG_EXIT, "recvfrom", 3, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_SHUTDOWN_E */ { SYSDIG_ENTER, "shutdown", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "how", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SOCKET_SHUTDOWN_X */ { SYSDIG_EXIT, "shutdown", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_GETSOCKNAME_E */ { SYSDIG_ENTER, "getsockname", 0},
  /* SYSDIG_SOCKET_GETSOCKNAME_X */ { SYSDIG_EXIT, "getsockname", 0},
  /* SYSDIG_SOCKET_GETPEERNAME_E */ { SYSDIG_ENTER, "getpeername", 0},
  /* SYSDIG_SOCKET_GETPEERNAME_X */ { SYSDIG_EXIT, "getpeername", 0},
  /* SYSDIG_SOCKET_SOCKETPAIR_E */ { SYSDIG_ENTER, "socketpair", 3, { { "domain", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_DEC}, { "type", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "proto", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_SOECKETPAIR_X */ { SYSDIG_EXIT, "socketpair", 5, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "fd1", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "fd2", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "source", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "peer", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SOCKET_SETSOCKOSYSDIG_TYPE_E */ { SYSDIG_ENTER, "setsockopt", 0},
  /* SYSDIG_SOCKET_SETSOCKOSYSDIG_TYPE_X */ { SYSDIG_EXIT, "setsockopt", 0},
  /* SYSDIG_SOCKET_GETSOCKOSYSDIG_TYPE_E */ { SYSDIG_ENTER, "getsockopt", 0},
  /* SYSDIG_SOCKET_GETSOCKOSYSDIG_TYPE_X */ { SYSDIG_EXIT, "getsockopt", 0},
  /* SYSDIG_SOCKET_SENDMSG_E */ { SYSDIG_ENTER, "sendmsg", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_SENDMSG_X */ { SYSDIG_EXIT, "sendmsg", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_SENDMMSG_E */ { SYSDIG_ENTER, "sendmmsg", 0},
  /* SYSDIG_SOCKET_SENDMMSG_X */ { SYSDIG_EXIT, "sendmmsg", 0},
  /* SYSDIG_SOCKET_RECVMSG_E */ { SYSDIG_ENTER, "recvmsg", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SOCKET_RECVMSG_X */ { SYSDIG_EXIT, "recvmsg", 4, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SOCKET_RECVMMSG_E */ { SYSDIG_ENTER, "recvmmsg", 0},
  /* SYSDIG_SOCKET_RECVMMSG_X */ { SYSDIG_EXIT, "recvmmsg", 0},
  /* SYSDIG_SOCKET_ACCEPT4_E */ { SYSDIG_ENTER, "accept", 1, { { "flags", SYSDIG_TYPE_INT32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SOCKET_ACCEPT4_X */ { SYSDIG_EXIT, "accept", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "tuple", SYSDIG_TYPE_SOCKTUPLE, SYSDIG_PRINT_FORMAT_NA}, { "queuepct", SYSDIG_TYPE_UINT8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_CREAT_E */ { SYSDIG_ENTER, "creat", 0},
  /* SYSDIG_SYSCALL_CREAT_X */ { SYSDIG_EXIT, "creat", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "name", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA}, { "mode", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SOCKET_PIPE_E */ { SYSDIG_ENTER, "pipe", 0},
  /* SYSDIG_SOCKET_PIPE_X */ { SYSDIG_EXIT, "pipe", 4, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "fd1", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "fd2", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "ino", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_EVENTFD_E */ { SYSDIG_ENTER, "eventfd", 2, { { "initval", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_EVENTFD_X */ { SYSDIG_EXIT, "eventfd", 1, { { "res", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_FUTEX_E */ { SYSDIG_ENTER, "futex", 3, { { "addr", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "op", SYSDIG_TYPE_FLAGS16, SYSDIG_PRINT_FORMAT_HEX}, { "val", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_FUTEX_X */ { SYSDIG_EXIT, "futex", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_STAT_E */ { SYSDIG_ENTER, "stat", 0},
  /* SYSDIG_SYSCALL_STAT_X */ { SYSDIG_EXIT, "stat", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_LSTAT_E */ { SYSDIG_ENTER, "lstat", 0},
  /* SYSDIG_SYSCALL_LSTAT_X */ { SYSDIG_EXIT, "lstat", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_FSTAT_E */ { SYSDIG_ENTER, "fstat", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_FSTAT_X */ { SYSDIG_EXIT, "fstat", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_STAT64_E */ { SYSDIG_ENTER, "stat64", 0},
  /* SYSDIG_SYSCALL_STAT64_X */ { SYSDIG_EXIT, "stat64", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_LSTAT64_E */ { SYSDIG_ENTER, "lstat64", 0},
  /* SYSDIG_SYSCALL_LSTAT64_X */ { SYSDIG_EXIT, "lstat64", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_FSTAT64_E */ { SYSDIG_ENTER, "fstat64", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_FSTAT64_X */ { SYSDIG_EXIT, "fstat64", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_EPOLLWAIT_E */ { SYSDIG_ENTER, "epoll_wait", 1, { { "maxevents", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_EPOLLWAIT_X */ { SYSDIG_EXIT, "epoll_wait", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_POLL_E */ { SYSDIG_ENTER, "poll", 2, { { "fds", SYSDIG_TYPE_FDLIST, SYSDIG_PRINT_FORMAT_DEC}, { "timeout", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_POLL_X */ { SYSDIG_EXIT, "poll", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "fds", SYSDIG_TYPE_FDLIST, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SELECT_E */ { SYSDIG_ENTER, "select", 0},
  /* SYSDIG_SYSCALL_SELECT_X */ { SYSDIG_EXIT, "select", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_NEWSELECT_E */ { SYSDIG_ENTER, "select", 0},
  /* SYSDIG_SYSCALL_NEWSELECT_X */ { SYSDIG_EXIT, "select", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_LSEEK_E */ { SYSDIG_ENTER, "lseek", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "offset", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "whence", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_LSEEK_X */ { SYSDIG_EXIT, "lseek", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_LLSEEK_E */ { SYSDIG_ENTER, "llseek", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "offset", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "whence", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_LLSEEK_X */ { SYSDIG_EXIT, "llseek", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_IOCTL_E */ { SYSDIG_ENTER, "ioctl", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "request", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_IOCTL_X */ { SYSDIG_EXIT, "ioctl", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_GETCWD_E */ { SYSDIG_ENTER, "getcwd", 0},
  /* Note: path is SYSDIG_TYPE_CHARBUF and not SYSDIG_TYPE_FSPATH because we assume it's abosulte and will never need resolution */
  /* SYSDIG_SYSCALL_GETCWD_X */ { SYSDIG_EXIT, "getcwd", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "path", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* Note: path is SYSDIG_TYPE_CHARBUF and not SYSDIG_TYPE_FSPATH because we don't want it to be resolved, since the event handler already changes it */
  /* SYSDIG_SYSCALL_CHDIR_E */ { SYSDIG_ENTER, "chdir", 0},
  /* SYSDIG_SYSCALL_CHDIR_X */ { SYSDIG_EXIT, "chdir", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "path", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_FCHDIR_E */ { SYSDIG_ENTER, "fchdir", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_FCHDIR_X */ { SYSDIG_EXIT, "fchdir", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MKDIR_E */ { SYSDIG_ENTER, "mkdir", 2, { { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA}, { "mode", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_MKDIR_X */ { SYSDIG_EXIT, "mkdir", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_RMDIR_E */ { SYSDIG_ENTER, "rmdir", 1, { { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_RMDIR_X */ { SYSDIG_EXIT, "rmdir", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_OPENAT_E */ { SYSDIG_ENTER, "openat", 4, { { "dirfd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "name", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "mode", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_OPENAT_X */ { SYSDIG_EXIT, "openat", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_LINK_E */ { SYSDIG_ENTER, "link", 2, { { "oldpath", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA}, { "newpath", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_LINK_X */ { SYSDIG_EXIT, "link", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_LINKAT_E */ { SYSDIG_ENTER, "linkat", 4, { { "olddir", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "oldpath", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "newdir", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "newpath", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_LINKAT_X */ { SYSDIG_EXIT, "linkat", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_UNLINK_E */ { SYSDIG_ENTER, "unlink", 1, { { "path", SYSDIG_TYPE_FSPATH, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_UNLINK_X */ { SYSDIG_EXIT, "unlink", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_UNLINKAT_E */ { SYSDIG_ENTER, "unlinkat", 2, { { "dirfd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "name", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_UNLINKAT_X */ { SYSDIG_EXIT, "unlinkat", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PREAD_E */ { SYSDIG_ENTER, "pread", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "pos", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PREAD_X */ { SYSDIG_EXIT, "pread", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_PWRITE_E */ { SYSDIG_ENTER, "pwrite", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "pos", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PWRITE_X */ { SYSDIG_EXIT, "pwrite", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_READV_E */ { SYSDIG_ENTER, "readv", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_READV_X */ { SYSDIG_EXIT, "readv", 3, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_WRITEV_E */ { SYSDIG_ENTER, "writev", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_WRITEV_X */ { SYSDIG_EXIT, "writev", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_PREADV_E */ { SYSDIG_ENTER, "preadv", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "pos", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PREADV_X */ { SYSDIG_EXIT, "preadv", 3, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_PWRITEV_E */ { SYSDIG_ENTER, "pwritev", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "pos", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PWRITEV_X */ { SYSDIG_EXIT, "pwritev", 2, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "data", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA} } },
  /* SYSDIG_SYSCALL_DUP_E */ { SYSDIG_ENTER, "dup", 1, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_DUP_X */ { SYSDIG_EXIT, "dup", 1, { { "res", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SIGNALFD_E */ { SYSDIG_ENTER, "signalfd", 3, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "mask", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_HEX}, { "flags", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_SIGNALFD_X */ { SYSDIG_EXIT, "signalfd", 1, { { "res", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_KILL_E */ { SYSDIG_ENTER, "kill", 2, { { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "sig", SYSDIG_TYPE_SIGTYPE, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_KILL_X */ { SYSDIG_EXIT, "kill", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_TKILL_E */ { SYSDIG_ENTER, "tkill", 2, { { "tid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "sig", SYSDIG_TYPE_SIGTYPE, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_TKILL_X */ { SYSDIG_EXIT, "tkill", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_TGKILL_E */ { SYSDIG_ENTER, "tgkill", 3, { { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "tid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "sig", SYSDIG_TYPE_SIGTYPE, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_TGKILL_X */ { SYSDIG_EXIT, "tgkill", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_NANOSLEEP_E */ { SYSDIG_ENTER, "nanosleep", 1, { { "interval", SYSDIG_TYPE_RELTIME, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_NANOSLEEP_X */ { SYSDIG_EXIT, "nanosleep", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_TIMERFD_CREATE_E */ { SYSDIG_ENTER, "timerfd_create", 2, { { "clockid", SYSDIG_TYPE_UINT8, SYSDIG_PRINT_FORMAT_DEC}, { "flags", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_TIMERFD_CREATE_X */ { SYSDIG_EXIT, "timerfd_create", 1, { { "res", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_INOTIFY_INIT_E */ { SYSDIG_ENTER, "inotify_init", 1, { { "flags", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_INOTIFY_INIT_X */ { SYSDIG_EXIT, "inotify_init", 1, { { "res", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_GETRLIMIT_E */ { SYSDIG_ENTER, "getrlimit", 1, { { "resource", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_GETRLIMIT_X */ { SYSDIG_EXIT, "getrlimit", 3, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "cur", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "max", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SETRLIMIT_E */ { SYSDIG_ENTER, "setrlimit", 1, { { "resource", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SETRLIMIT_X */ { SYSDIG_EXIT, "setrlimit", 3, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "cur", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "max", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PRLIMIT_E */ { SYSDIG_ENTER, "prlimit", 2, { { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "resource", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_PRLIMIT_X */ { SYSDIG_EXIT, "prlimit", 5, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "newcur", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "newmax", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "oldcur", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "oldmax", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SCHEDSWITCH_1_E */ { SYSDIG_ENTER, "switch", 1, { { "next", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SCHEDSWITCH_1_X */ { SYSDIG_EXIT, "NA2", 0},
  /* SYSDIG_DROP_E */ { SYSDIG_ENTER, "drop", 1, { { "ratio", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_DROP_X */ { SYSDIG_EXIT, "drop", 1, { { "ratio", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_FCNTL_E */ { SYSDIG_ENTER, "fcntl", 2, { { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "cmd", SYSDIG_TYPE_FLAGS8, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_FCNTL_X */ { SYSDIG_EXIT, "fcntl", 1, { { "res", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SCHEDSWITCH_6_E */ { SYSDIG_ENTER, "switch", 6, { { "next", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "pgft_maj", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "pgft_min", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SCHEDSWITCH_6_X */ { SYSDIG_EXIT, "NA2", 0},
  /* SYSDIG_SYSCALL_EXECVE_13_E */ { SYSDIG_ENTER, "execve", 0},
  /* SYSDIG_SYSCALL_EXECVE_13_X */ { SYSDIG_EXIT, "execve", 13, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "exe", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "args", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA}, { "tid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "ptid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "cwd", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "fdlimit", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "pgft_maj", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "pgft_min", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_CLONE_16_E */ { SYSDIG_ENTER, "clone", 0},
  /* SYSDIG_CLONE_16_X */ { SYSDIG_EXIT, "clone", 16, { { "res", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "exe", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "args", SYSDIG_TYPE_BYTEBUF, SYSDIG_PRINT_FORMAT_NA}, { "tid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "pid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "ptid", SYSDIG_TYPE_PID, SYSDIG_PRINT_FORMAT_DEC}, { "cwd", SYSDIG_TYPE_CHARBUF, SYSDIG_PRINT_FORMAT_NA}, { "fdlimit", SYSDIG_TYPE_INT64, SYSDIG_PRINT_FORMAT_DEC}, { "pgft_maj", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "pgft_min", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "uid", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "gid", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_BRK_4_E */ { SYSDIG_ENTER, "brk", 1, { { "addr", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_BRK_4_X */ { SYSDIG_EXIT, "brk", 4, { { "res", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MMAP_E */ { SYSDIG_ENTER, "mmap", 6, { { "addr", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "length", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "prot", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "offset", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MMAP_X */ { SYSDIG_EXIT, "mmap", 4, { { "res", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MMAP2_E */ { SYSDIG_ENTER, "mmap2", 6, { { "addr", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "length", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "prot", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX}, { "fd", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "pgoffset", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MMAP2_X */ { SYSDIG_EXIT, "mmap2", 4, { { "res", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MUNMAP_E */ { SYSDIG_ENTER, "munmap", 2, { { "addr", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_HEX}, { "length", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_MUNMAP_X */ { SYSDIG_EXIT, "munmap", 4, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}, { "vm_size", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_rss", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC}, { "vm_swap", SYSDIG_TYPE_UINT32, SYSDIG_PRINT_FORMAT_DEC} } },
  /* SYSDIG_SYSCALL_SPLICE_E */ { SYSDIG_ENTER, "splice", 4, { { "fd_in", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "fd_out", SYSDIG_TYPE_FD, SYSDIG_PRINT_FORMAT_DEC}, { "size", SYSDIG_TYPE_UINT64, SYSDIG_PRINT_FORMAT_DEC}, { "flags", SYSDIG_TYPE_FLAGS32, SYSDIG_PRINT_FORMAT_HEX} } },
  /* SYSDIG_SYSCALL_SPLICE_X */ { SYSDIG_EXIT, "splice", 1, { { "res", SYSDIG_TYPE_ERRNO, SYSDIG_PRINT_FORMAT_DEC}} }
};

/* **************************************************** */

int pfring_mod_sysdig_open(pfring *ring) {
  u_int8_t device_id = 0;
  pfring_sysdig *sysdig = NULL;

  ring->close                    = pfring_mod_sysdig_close;
  ring->recv                     = pfring_mod_sysdig_recv;
  ring->poll                     = pfring_mod_sysdig_poll;
  ring->enable_ring              = pfring_mod_sysdig_enable_ring;
  ring->set_poll_watermark       = pfring_mod_sysdig_set_poll_watermark;
  ring->set_socket_mode          = pfring_mod_sysdig_set_socket_mode;
  ring->stats                    = pfring_mod_sysdig_stats;
  ring->get_bound_device_ifindex = pfring_mod_sysdig_get_bound_device_ifindex;
  ring->set_bpf_filter           = pfring_mod_sysdig_set_bpf_filter;
  ring->remove_bpf_filter        = pfring_mod_sysdig_remove_bpf_filter;

  ring->priv_data = malloc(sizeof(pfring_sysdig));

  if(ring->priv_data == NULL)
    goto sysdig_ret_error;

  memset(ring->priv_data, 0, sizeof(pfring_sysdig));
  sysdig = (pfring_sysdig*)ring->priv_data;

  sysdig->num_devices = sysconf(_SC_NPROCESSORS_ONLN); /* # devices = # CPUs */

  if(sysdig->num_devices > SYSDIG_MAX_NUM_DEVICES) {
    fprintf(stderr, "Internal error: too many devices %u\n", sysdig->num_devices);
    return(-1);
  }

  sysdig->bytes_watermark = SYSDIG_DEFAULT_DATA_AVAIL;
  if(ring->caplen > MAX_CAPLEN) ring->caplen = MAX_CAPLEN;
  ring->poll_duration = DEFAULT_POLL_DURATION;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    char device_name[48];

    snprintf(device_name, sizeof(device_name), "/dev/sysdig%u", device_id);

    if((sysdig->devices[device_id].fd = open((char *)device_name, O_RDWR | O_SYNC)) < 0) {
      fprintf(stderr, "Error opening %s\n", device_name);
      goto sysdig_open_error;
    }

    /* Prevent capture until the ring is enabled */
    if(ioctl(sysdig->devices[device_id].fd, SYSDIG_IOCTL_DISABLE_DROPPING_MODE))
      return(-1);

    if(ioctl(sysdig->devices[device_id].fd, SYSDIG_IOCTL_DISABLE_CAPTURE))
      return(-1);

    if((sysdig->devices[device_id].ring_mmap =
	(char*)mmap(0, SYSDIG_RING_LEN,
		    PROT_READ, MAP_SHARED,
		    sysdig->devices[device_id].fd, 0)) == MAP_FAILED) {
      fprintf(stderr, "Unable to mmap ring for %s\n", device_name);
      goto sysdig_open_error;
    }

    sysdig->devices[device_id].ring_info =
      (struct sysdig_ring_info*)mmap(0, sizeof(struct sysdig_ring_info),
				     PROT_READ | PROT_WRITE,
				     MAP_SHARED,
				     sysdig->devices[device_id].fd, 0);
    if(sysdig->devices[device_id].ring_info == MAP_FAILED) {
      fprintf(stderr, "Unable to mmap info ring for %s\n", device_name);
      goto sysdig_open_error;
    }

  }
  return(0); /* Everything looks good so far */

 sysdig_open_error:
  pfring_mod_sysdig_close(ring);

 sysdig_ret_error:
  return(-1);
}

/* **************************************************** */

void pfring_mod_sysdig_close(pfring *ring) {
  pfring_sysdig *sysdig;
  u_int8_t device_id = 0;

  if(ring->priv_data == NULL)
    return;

  sysdig = (pfring_sysdig *)ring->priv_data;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    if(sysdig->devices[device_id].ring_info)
      munmap(sysdig->devices[device_id].ring_info, sizeof(struct sysdig_ring_info));

    if(sysdig->devices[device_id].ring_mmap)
      munmap(sysdig->devices[device_id].ring_mmap, SYSDIG_RING_LEN);

    if(sysdig->devices[device_id].fd)
      close(sysdig->devices[device_id].fd);
  }
}

/* **************************************************** */

static u_int32_t pfring_sysdig_get_data_available(pfring_sysdig_device *dev) {
  u_int32_t rc, head = dev->ring_info->head, tail = dev->ring_info->tail;

  if(tail > head) /* Ring wrap */
    rc = RING_BUF_SIZE - tail + head;
  else
    rc = head - tail;

  // printf("%s() : %u\n", __FUNCTION__, rc);
  return(rc);
}

/* **************************************************** */

static void sysdig_get_first_event(pfring_sysdig *sysdig,
				   pfring_sysdig_device *dev,
				   struct sysdig_event_header **ev) {
  u_int32_t next_tail = dev->ring_info->tail + dev->last_evt_read_len;

  /* Check if we have a packet already read but not taken into account */
  if(dev->last_evt_read_len > 0) {
    if(next_tail >= RING_BUF_SIZE)
      next_tail = next_tail - RING_BUF_SIZE; /* Start over (ring wrap) */

    /* Event consumed: update tail */
    dev->ring_info->tail = next_tail;
  }

  if(pfring_sysdig_get_data_available(dev) < sysdig->bytes_watermark /* Too little data */)
    *ev = NULL, dev->last_evt_read_len = 0;
  else {
    // printf("%u ", dev->ring_info->tail);
    *ev = (struct sysdig_event_header*)(dev->ring_mmap + next_tail);
    dev->last_evt_read_len = (*ev)->event_len;

    // printf("%u(%u) ", dev->ring_info->tail, (*ev)->event_type);
  }
}

/* **************************************************** */

int pfring_mod_sysdig_recv(pfring *ring, u_char** buffer, u_int buffer_len,
			   struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet) {

  u_int8_t device_id, ret_device_id = 0;
  pfring_sysdig *sysdig;
  struct sysdig_event_header *ret_event = NULL;

  if(ring->priv_data == NULL)
    return(-1);

  sysdig = (pfring_sysdig *)ring->priv_data;

  if(ring->reentrant)
    pthread_rwlock_wrlock(&ring->rx_lock);

 check_and_poll:
  if(ring->break_recv_loop)
    goto exit; /* retval = 0 */

  __sync_synchronize();

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    struct sysdig_event_header *this_event;

    sysdig_get_first_event(sysdig, &sysdig->devices[device_id], &this_event);

    if(this_event) {
      if(ret_event == NULL)
	ret_event = this_event, ret_device_id = device_id;
      else {
	if(this_event->ts < ret_event->ts) {
	  /* This event is older than the previous one hence I need
	     to push pack the ret_event */

	  sysdig->devices[ret_device_id].last_evt_read_len = 0;
	  ret_event = this_event, ret_device_id = device_id;
	} else {
	  sysdig->devices[device_id].last_evt_read_len = 0; /* Ignore this event */
	}
      }
    }
  }

  if(ret_event == NULL) {
    /* No event returned */

    if(wait_for_incoming_packet) {
      usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
      goto check_and_poll;
    }
  } else {
    if(buffer_len > 0) {
      /* one copy */
      u_int len = ret_event->event_len;

      if(len > ring->caplen) len = ring->caplen;
      if(len > buffer_len)  len = buffer_len;

      memcpy(*buffer, ret_event, len);
      hdr->caplen = len, hdr->len = ret_event->event_len;
    } else {
      /* zero copy */
      *buffer = (u_char*)ret_event;
      hdr->caplen = hdr->len = ret_event->event_len;
    }

    hdr->extended_hdr.timestamp_ns = ret_event->ts;
    hdr->extended_hdr.pkt_hash = hdr->extended_hdr.if_index = ret_device_id; /* CPU id */

    /*
      The two statements below are kinda a waste of time as timestamp_ns
      is more than enough
    */
    hdr->ts.tv_sec = hdr->extended_hdr.timestamp_ns / 1000000000,
      hdr->ts.tv_usec = (hdr->extended_hdr.timestamp_ns / 1000) % 1000000;
  }

 exit:
  if(ring->reentrant)
    pthread_rwlock_unlock(&ring->rx_lock);

  return(ret_event ? 1 : 0);
}

/* **************************************************** */

int pfring_mod_sysdig_enable_ring(pfring *ring) {
  u_int32_t device_id;
  pfring_sysdig *sysdig;
  u_char *buffer;
  struct pfring_pkthdr hdr;

  if(ring->priv_data == NULL)
    return(-1);

  sysdig = (pfring_sysdig *)ring->priv_data;

  /* Flush any pending event */
  while(pfring_mod_sysdig_recv(ring, &buffer, 0, &hdr, 0) == 1)
    ;

  /* Enable the ring */
  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    if(ioctl(sysdig->devices[device_id].fd, SYSDIG_IOCTL_ENABLE_CAPTURE))
      return(-1);
  }

  return(0);
}

/* **************************************************** */

int pfring_mod_sysdig_poll(pfring *ring, u_int wait_duration) {
  pfring_sysdig *sysdig;
  u_int8_t device_id;

  if(ring->priv_data == NULL)
    return(-1);

  sysdig = (pfring_sysdig *)ring->priv_data;

  while(1) {
    for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
      if(pfring_sysdig_get_data_available(&sysdig->devices[device_id]) >= sysdig->bytes_watermark)
	return(1);
    }

    /* No data found */
    if(wait_duration == 0) return(0);

    usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
    wait_duration--;
  }

  return(1); /* Not reached */
}

/* ******************************* */

int pfring_mod_sysdig_set_socket_mode(pfring *ring, socket_mode mode) {
  return((mode == recv_only_mode) ? 0 : -1);
}

/* ******************************* */

int pfring_mod_sysdig_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  pfring_sysdig *sysdig = NULL;

  if(ring->priv_data == NULL)
    return(-1);

  sysdig = (pfring_sysdig*)ring->priv_data;
  sysdig->bytes_watermark = (watermark <= 1) ? 1 /* Force to return at each event */: (watermark * 8192);

  return(0);
}

/* ******************************* */

int pfring_mod_sysdig_stats(pfring *ring, pfring_stat *stats) {
  u_int8_t device_id;
  pfring_sysdig *sysdig = NULL;

  if(ring->priv_data == NULL)
    return(-1);
  else
    sysdig = (pfring_sysdig*)ring->priv_data;

  stats->recv = 0, stats->drop = 0;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    stats->recv += sysdig->devices[device_id].ring_info->n_evts,
      stats->drop +=
      sysdig->devices[device_id].ring_info->n_drops_buffer +
      sysdig->devices[device_id].ring_info->n_drops_pf;
  }

  return(0);
}

/* **************************************************** */

int pfring_mod_sysdig_get_bound_device_ifindex(pfring *ring, int *if_index) {
  *if_index = 0; /* Dummy index */

  return(0);
}

/* **************************************************** */

/*
  This is a simple filter that will be extended in future version of the code.
  The currently accepted syntax is "evt.type=X or evt.type=Y ..." that is a subset
  of the syntax supported by the sysdig command
*/
int pfring_mod_sysdig_set_bpf_filter(pfring *ring, char *filter_buffer) {
  u_int32_t device_id;
  pfring_sysdig *sysdig;
  char *filter, *item, *where;

  if(ring->priv_data == NULL)
    return(-1);

  sysdig = (pfring_sysdig *)ring->priv_data;

  /* Remove old filter, if any */
  if(pfring_mod_sysdig_remove_bpf_filter(ring) < 0) return(-1);

  if((filter = strdup(filter_buffer)) == NULL) return(-2);

  item = strtok_r(filter, " ", &where);

  while(item != NULL) {
    if(strncmp(item, "evt.type=", 9) == 0) {
      int j;

      item = &item[9];

      for(j=0; j<SYSDIG_EVENT_MAX; j++) {
	/*
	  As multiple events with the same name can be registered,
	  this loop goes up until the end of sysdig_events
	*/
	if(strcmp(sysdig_events[j].name, item) == 0) {
	  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
	    if(ioctl(sysdig->devices[device_id].fd, SYSDIG_IOCTL_MASK_SET_EVENT, j)) {
	      free(filter);
	      return(-1);
	    }
	  }
	}
      }
    } else if(strcmp(item, "or") == 0) {
      /* "or" term: to skip */
    } else {
      printf("WARNING: ignoring sysdig filter item '%s'\n", item);
    }

    item = strtok_r(NULL, " ", &where);
  }

  free(filter);
  return(0);
}

/* **************************************************** */

int pfring_mod_sysdig_remove_bpf_filter(pfring *ring) {
  u_int32_t device_id;
  pfring_sysdig *sysdig;

  if(ring->priv_data == NULL)
    return(-1);

  sysdig = (pfring_sysdig *)ring->priv_data;

  for(device_id = 0; device_id < sysdig->num_devices; device_id++) {
    if(ioctl(sysdig->devices[device_id].fd, SYSDIG_IOCTL_MASK_ZERO_EVENTS)) {
      return(-1);
    }
  }

  return(0);
}

/* ****************************************************** */

char* sysdig_event2name(enum sysdig_event_type event_type) {
  static char event_buf[SYSDIG_MAX_NAME_LEN+4];

  snprintf(event_buf, sizeof(event_buf), "%c %s",
	   (sysdig_events[event_type].mode == SYSDIG_ENTER) ? '<' : '>',
	   sysdig_events[event_type].name);

  return(event_buf);
};

/* ****************************************************** */

const struct sysdig_event_info* sysdig_event2info(enum sysdig_event_type event_type) {
  return(&sysdig_events[event_type]);
}
