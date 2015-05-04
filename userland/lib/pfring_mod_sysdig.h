/*
 *
 * (C) 2014 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_SYSDIG_H_
#define _PFRING_MOD_SYSDIG_H_

#define RING_BUF_SIZE                 1024 * 8192
#define SYSDIG_RING_LEN               RING_BUF_SIZE * 2
#define SYSDIG_DEFAULT_DATA_AVAIL     100000
#define BUFFER_EMPTY_WAIT_TIME_MS     30

#define SYSDIG_MAX_NUM_DEVICES        64

#define SYSDIG_MAX_NAME_LEN           32
#define SYSDIG_MAX_EVENT_PARAMS       16 /* Max number of parameters an event can have */


/* From sysdig's ppm_events_public.h */
#define SYSDIG_IOCTL_MAGIC	           's'
#define SYSDIG_IOCTL_DISABLE_CAPTURE       _IO(SYSDIG_IOCTL_MAGIC, 0)
#define SYSDIG_IOCTL_ENABLE_CAPTURE        _IO(SYSDIG_IOCTL_MAGIC, 1)
#define SYSDIG_IOCTL_DISABLE_DROPPING_MODE _IO(SYSDIG_IOCTL_MAGIC, 2)
#define SYSDIG_IOCTL_ENABLE_DROPPING_MODE  _IO(SYSDIG_IOCTL_MAGIC, 3)
#define SYSDIG_IOCTL_SET_SNAPLEN           _IO(SYSDIG_IOCTL_MAGIC, 4)
#define SYSDIG_IOCTL_MASK_ZERO_EVENTS      _IO(SYSDIG_IOCTL_MAGIC, 5)
#define SYSDIG_IOCTL_MASK_SET_EVENT        _IO(SYSDIG_IOCTL_MAGIC, 6)
#define SYSDIG_IOCTL_MASK_UNSET_EVENT      _IO(SYSDIG_IOCTL_MAGIC, 7)

/* From sysdig's ppm_event_type in ppm_events_public.h */
enum sysdig_event_type {
  SYSDIG_GENERIC_E = 0,
  SYSDIG_GENERIC_X = 1,
  SYSDIG_SYSCALL_OPEN_E = 2,
  SYSDIG_SYSCALL_OPEN_X = 3,
  SYSDIG_SYSCALL_CLOSE_E = 4,
  SYSDIG_SYSCALL_CLOSE_X = 5,
  SYSDIG_SYSCALL_READ_E = 6,
  SYSDIG_SYSCALL_READ_X = 7,
  SYSDIG_SYSCALL_WRITE_E = 8,
  SYSDIG_SYSCALL_WRITE_X = 9,
  SYSDIG_SYSCALL_BRK_1_E = 10,
  SYSDIG_SYSCALL_BRK_1_X = 11,
  SYSDIG_SYSCALL_EXECVE_8_E = 12,
  SYSDIG_SYSCALL_EXECVE_8_X = 13,
  SYSDIG_CLONE_11_E = 14,
  SYSDIG_CLONE_11_X = 15,
  SYSDIG_PROCEXIT_E = 16,
  SYSDIG_PROCEXIT_X = 17,	/* This should never be called */
  SYSDIG_SOCKET_SOCKET_E = 18,
  SYSDIG_SOCKET_SOCKET_X = 19,
  SYSDIG_SOCKET_BIND_E = 20,
  SYSDIG_SOCKET_BIND_X = 21,
  SYSDIG_SOCKET_CONNECT_E = 22,
  SYSDIG_SOCKET_CONNECT_X = 23,
  SYSDIG_SOCKET_LISTEN_E = 24,
  SYSDIG_SOCKET_LISTEN_X = 25,
  SYSDIG_SOCKET_ACCEPT_E = 26,
  SYSDIG_SOCKET_ACCEPT_X = 27,
  SYSDIG_SOCKET_SEND_E = 28,
  SYSDIG_SOCKET_SEND_X = 29,
  SYSDIG_SOCKET_SENDTO_E = 30,
  SYSDIG_SOCKET_SENDTO_X = 31,
  SYSDIG_SOCKET_RECV_E = 32,
  SYSDIG_SOCKET_RECV_X = 33,
  SYSDIG_SOCKET_RECVFROM_E = 34,
  SYSDIG_SOCKET_RECVFROM_X = 35,
  SYSDIG_SOCKET_SHUTDOWN_E = 36,
  SYSDIG_SOCKET_SHUTDOWN_X = 37,
  SYSDIG_SOCKET_GETSOCKNAME_E = 38,
  SYSDIG_SOCKET_GETSOCKNAME_X = 39,
  SYSDIG_SOCKET_GETPEERNAME_E = 40,
  SYSDIG_SOCKET_GETPEERNAME_X = 41,
  SYSDIG_SOCKET_SOCKETPAIR_E = 42,
  SYSDIG_SOCKET_SOCKETPAIR_X = 43,
  SYSDIG_SOCKET_SETSOCKOPT_E = 44,
  SYSDIG_SOCKET_SETSOCKOPT_X = 45,
  SYSDIG_SOCKET_GETSOCKOPT_E = 46,
  SYSDIG_SOCKET_GETSOCKOPT_X = 47,
  SYSDIG_SOCKET_SENDMSG_E = 48,
  SYSDIG_SOCKET_SENDMSG_X = 49,
  SYSDIG_SOCKET_SENDMMSG_E = 50,
  SYSDIG_SOCKET_SENDMMSG_X = 51,
  SYSDIG_SOCKET_RECVMSG_E = 52,
  SYSDIG_SOCKET_RECVMSG_X = 53,
  SYSDIG_SOCKET_RECVMMSG_E = 54,
  SYSDIG_SOCKET_RECVMMSG_X = 55,
  SYSDIG_SOCKET_ACCEPT4_E = 56,
  SYSDIG_SOCKET_ACCEPT4_X = 57,
  SYSDIG_SYSCALL_CREAT_E = 58,
  SYSDIG_SYSCALL_CREAT_X = 59,
  SYSDIG_SYSCALL_PIPE_E = 60,
  SYSDIG_SYSCALL_PIPE_X = 61,
  SYSDIG_SYSCALL_EVENTFD_E = 62,
  SYSDIG_SYSCALL_EVENTFD_X = 63,
  SYSDIG_SYSCALL_FUTEX_E = 64,
  SYSDIG_SYSCALL_FUTEX_X = 65,
  SYSDIG_SYSCALL_STAT_E = 66,
  SYSDIG_SYSCALL_STAT_X = 67,
  SYSDIG_SYSCALL_LSTAT_E = 68,
  SYSDIG_SYSCALL_LSTAT_X = 69,
  SYSDIG_SYSCALL_FSTAT_E = 70,
  SYSDIG_SYSCALL_FSTAT_X = 71,
  SYSDIG_SYSCALL_STAT64_E = 72,
  SYSDIG_SYSCALL_STAT64_X = 73,
  SYSDIG_SYSCALL_LSTAT64_E = 74,
  SYSDIG_SYSCALL_LSTAT64_X = 75,
  SYSDIG_SYSCALL_FSTAT64_E = 76,
  SYSDIG_SYSCALL_FSTAT64_X = 77,
  SYSDIG_SYSCALL_EPOLLWAIT_E = 78,
  SYSDIG_SYSCALL_EPOLLWAIT_X = 79,
  SYSDIG_SYSCALL_POLL_E = 80,
  SYSDIG_SYSCALL_POLL_X = 81,
  SYSDIG_SYSCALL_SELECT_E = 82,
  SYSDIG_SYSCALL_SELECT_X = 83,
  SYSDIG_SYSCALL_NEWSELECT_E = 84,
  SYSDIG_SYSCALL_NEWSELECT_X = 85,
  SYSDIG_SYSCALL_LSEEK_E = 86,
  SYSDIG_SYSCALL_LSEEK_X = 87,
  SYSDIG_SYSCALL_LLSEEK_E = 88,
  SYSDIG_SYSCALL_LLSEEK_X = 89,
  SYSDIG_SYSCALL_IOCTL_E = 90,
  SYSDIG_SYSCALL_IOCTL_X = 91,
  SYSDIG_SYSCALL_GETCWD_E = 92,
  SYSDIG_SYSCALL_GETCWD_X = 93,
  SYSDIG_SYSCALL_CHDIR_E = 94,
  SYSDIG_SYSCALL_CHDIR_X = 95,
  SYSDIG_SYSCALL_FCHDIR_E = 96,
  SYSDIG_SYSCALL_FCHDIR_X = 97,
  SYSDIG_SYSCALL_MKDIR_E = 98,
  SYSDIG_SYSCALL_MKDIR_X = 99,
  SYSDIG_SYSCALL_RMDIR_E = 100,
  SYSDIG_SYSCALL_RMDIR_X = 101,
  SYSDIG_SYSCALL_OPENAT_E = 102,
  SYSDIG_SYSCALL_OPENAT_X = 103,
  SYSDIG_SYSCALL_LINK_E = 104,
  SYSDIG_SYSCALL_LINK_X = 105,
  SYSDIG_SYSCALL_LINKAT_E = 106,
  SYSDIG_SYSCALL_LINKAT_X = 107,
  SYSDIG_SYSCALL_UNLINK_E = 108,
  SYSDIG_SYSCALL_UNLINK_X = 109,
  SYSDIG_SYSCALL_UNLINKAT_E = 110,
  SYSDIG_SYSCALL_UNLINKAT_X = 111,
  SYSDIG_SYSCALL_PREAD_E = 112,
  SYSDIG_SYSCALL_PREAD_X = 113,
  SYSDIG_SYSCALL_PWRITE_E = 114,
  SYSDIG_SYSCALL_PWRITE_X = 115,
  SYSDIG_SYSCALL_READV_E = 116,
  SYSDIG_SYSCALL_READV_X = 117,
  SYSDIG_SYSCALL_WRITEV_E = 118,
  SYSDIG_SYSCALL_WRITEV_X = 119,
  SYSDIG_SYSCALL_PREADV_E = 120,
  SYSDIG_SYSCALL_PREADV_X = 121,
  SYSDIG_SYSCALL_PWRITEV_E = 122,
  SYSDIG_SYSCALL_PWRITEV_X = 123,
  SYSDIG_SYSCALL_DUP_E = 124,
  SYSDIG_SYSCALL_DUP_X = 125,
  SYSDIG_SYSCALL_SIGNALFD_E = 126,
  SYSDIG_SYSCALL_SIGNALFD_X = 127,
  SYSDIG_SYSCALL_KILL_E = 128,
  SYSDIG_SYSCALL_KILL_X = 129,
  SYSDIG_SYSCALL_TKILL_E = 130,
  SYSDIG_SYSCALL_TKILL_X = 131,
  SYSDIG_SYSCALL_TGKILL_E = 132,
  SYSDIG_SYSCALL_TGKILL_X = 133,
  SYSDIG_SYSCALL_NANOSLEEP_E = 134,
  SYSDIG_SYSCALL_NANOSLEEP_X = 135,
  SYSDIG_SYSCALL_TIMERFD_CREATE_E = 136,
  SYSDIG_SYSCALL_TIMERFD_CREATE_X = 137,
  SYSDIG_SYSCALL_INOTIFY_INIT_E = 138,
  SYSDIG_SYSCALL_INOTIFY_INIT_X = 139,
  SYSDIG_SYSCALL_GETRLIMIT_E = 140,
  SYSDIG_SYSCALL_GETRLIMIT_X = 141,
  SYSDIG_SYSCALL_SETRLIMIT_E = 142,
  SYSDIG_SYSCALL_SETRLIMIT_X = 143,
  SYSDIG_SYSCALL_PRLIMIT_E = 144,
  SYSDIG_SYSCALL_PRLIMIT_X = 145,
  SYSDIG_SCHEDSWITCH_1_E = 146,
  SYSDIG_SCHEDSWITCH_1_X = 147,	/* This should never be called */
  SYSDIG_DROP_E = 148,  /* For internal use */
  SYSDIG_DROP_X = 149,	/* For internal use */
  SYSDIG_SYSCALL_FCNTL_E = 150,  /* For internal use */
  SYSDIG_SYSCALL_FCNTL_X = 151,	/* For internal use */
  SYSDIG_SCHEDSWITCH_6_E = 152,
  SYSDIG_SCHEDSWITCH_6_X = 153,	/* This should never be called */
  SYSDIG_SYSCALL_EXECVE_13_E = 154,
  SYSDIG_SYSCALL_EXECVE_13_X = 155,
  SYSDIG_CLONE_16_E = 156,
  SYSDIG_CLONE_16_X = 157,
  SYSDIG_SYSCALL_BRK_4_E = 158,
  SYSDIG_SYSCALL_BRK_4_X = 159,
  SYSDIG_SYSCALL_MMAP_E = 160,
  SYSDIG_SYSCALL_MMAP_X = 161,
  SYSDIG_SYSCALL_MMAP2_E = 162,
  SYSDIG_SYSCALL_MMAP2_X = 163,
  SYSDIG_SYSCALL_MUNMAP_E = 164,
  SYSDIG_SYSCALL_MUNMAP_X = 165,
  SYSDIG_SYSCALL_SPLICE_E = 166,
  SYSDIG_SYSCALL_SPLICE_X = 167,
  SYSDIG_EVENT_MAX = 168
};

enum sysdig_param_type {
  SYSDIG_TYPE_NONE = 0,
  SYSDIG_TYPE_INT8 = 1,
  SYSDIG_TYPE_INT16 = 2,
  SYSDIG_TYPE_INT32 = 3,
  SYSDIG_TYPE_INT64 = 4,
  SYSDIG_TYPE_UINT8 = 5,
  SYSDIG_TYPE_UINT16 = 6,
  SYSDIG_TYPE_UINT32 = 7,
  SYSDIG_TYPE_UINT64 = 8,
  SYSDIG_TYPE_CHARBUF = 9,	/* A printable buffer of bytes, NULL terminated */
  SYSDIG_TYPE_BYTEBUF = 10, /* A raw buffer of bytes not suitable for printing */
  SYSDIG_TYPE_ERRNO = 11,	/* this is an INT64, but will be interpreted as an error code */
  SYSDIG_TYPE_SOCKADDR = 12, /* A sockaddr structure, 1byte family + data */
  SYSDIG_TYPE_SOCKTUPLE = 13, /* A sockaddr tuple,1byte family + 12byte data + 12byte data */
  SYSDIG_TYPE_FD = 14, /* An fd, 64bit */
  SYSDIG_TYPE_PID = 15, /* A pid/tid, 64bit */
  SYSDIG_TYPE_FDLIST = 16, /* A list of fds, 16bit count + count * (64bit fd + 16bit flags) */
  SYSDIG_TYPE_FSPATH = 17,	/* A string containing a relative or absolute file system path, null terminated */
  SYSDIG_TYPE_SYSCALLID = 18, /* A 16bit system call ID. Can be used as a key for the g_syscall_info_table table. */
  SYSDIG_TYPE_SIGTYPE = 19, /* An 8bit signal number */
  SYSDIG_TYPE_RELTIME = 20, /* A relative time. Seconds * 10^9  + nanoseconds. 64bit. */
  SYSDIG_TYPE_ABSTIME = 21, /* An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit. */
  SYSDIG_TYPE_PORT = 22, /* A TCP/UDP prt. 2 bytes. */
  SYSDIG_TYPE_L4PROTO = 23, /* A 1 byte IP protocol type. */
  SYSDIG_TYPE_SOCKFAMILY = 24, /* A 1 byte socket family. */
  SYSDIG_TYPE_BOOL = 25, /* A boolean value, 4 bytes. */
  SYSDIG_TYPE_IPV4ADDR = 26, /* A 4 byte raw IPv4 address. */
  SYSDIG_TYPE_DYN = 27, /* Type can vary depending on the context. Used for filter fields like evt.rawarg. */
  SYSDIG_TYPE_FLAGS8 = 28, /* this is an UINT8, but will be interpreted as 8 bit flags. */
  SYSDIG_TYPE_FLAGS16 = 29, /* this is an UINT16, but will be interpreted as 16 bit flags. */
  SYSDIG_TYPE_FLAGS32 = 30, /* this is an UINT32, but will be interpreted as 32 bit flags. */
};

enum sysdig_print_format {
  SYSDIG_PRINT_FORMAT_NA = 0,
  SYSDIG_PRINT_FORMAT_DEC = 1,	/* decimal */
  SYSDIG_PRINT_FORMAT_HEX = 2,	/* hexadecima */
  SYSDIG_PRINT_FORMAT_10_PADDED_DEC = 3, /* decimal padded to 10 digits, useful to print the fractional part of a ns timestamp */
};

enum sysdig_syscall_mode {
  SYSDIG_ENTER = 0,
  SYSDIG_EXIT = 1,
};

struct sysdig_param_info {
  char name[SYSDIG_MAX_NAME_LEN]; /**< Paramter name, e.g. 'size'. */
  enum sysdig_param_type type;    /**< Paramter type, e.g. 'u_int16', 'string'... */
  enum sysdig_print_format fmt;   /**< If this is a numeric parameter, this flag specifies if it should be rendered as decimal or hex. */
};

struct sysdig_event_info {
  enum sysdig_syscall_mode mode;  /**< Event mode (enter or exit). */
  char name[SYSDIG_MAX_NAME_LEN]; /**< Name. */
  u_int32_t nparams;              /**< Number of parameter in the params array. */
  struct sysdig_param_info params[SYSDIG_MAX_EVENT_PARAMS]; /**< parameters descriptions. */
};

struct sysdig_ring_info {
  volatile u_int32_t head;
  volatile u_int32_t tail;
  volatile u_int64_t n_evts;		 /* Total number of events that were received by the driver. */
  volatile u_int64_t n_drops_buffer;	 /* Number of dropped events (buffer full). */
  volatile u_int64_t n_drops_pf;	 /* Number of dropped events (page faults). */
  volatile u_int64_t n_preemptions;	 /* Number of preemptions. */
  volatile u_int64_t n_context_switches; /* Number of received context switch events. */
};

typedef struct {
  int		          fd;
  char                    *ring_mmap;
  struct sysdig_ring_info *ring_info;

  u_int32_t               last_evt_read_len;
} pfring_sysdig_device;

typedef struct {
  u_int8_t                num_devices;
  u_int32_t               bytes_watermark;
  pfring_sysdig_device    devices[SYSDIG_MAX_NUM_DEVICES];
} pfring_sysdig;

#pragma pack(push, 1)
struct sysdig_event_header {
  u_int64_t ts;         /* timestamp, in nanoseconds from epoch */
  u_int64_t thread_id;  /* the thread that generated this event */
  u_int32_t event_len;  /* the event len, including the header */
  u_int16_t event_type; /* the event type */
};
#pragma pack(pop)


int  pfring_mod_sysdig_open(pfring *ring);
void pfring_mod_sysdig_close(pfring *ring);
int  pfring_mod_sysdig_stats(pfring *ring, pfring_stat *stats);
int  pfring_mod_sysdig_recv(pfring *ring, u_char** buffer, u_int buffer_len,
			    struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_mod_sysdig_poll(pfring *ring, u_int wait_duration);
int  pfring_mod_sysdig_enable_ring(pfring *ring);
int  pfring_mod_sysdig_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_mod_sysdig_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_mod_sysdig_stats(pfring *ring, pfring_stat *stats);
int  pfring_mod_sysdig_get_bound_device_ifindex(pfring *ring, int *if_index);
int  pfring_mod_sysdig_set_bpf_filter(pfring *ring, char *filter_buffer);
int  pfring_mod_sysdig_remove_bpf_filter(pfring *ring);

/* Public functions */
char* sysdig_event2name(enum sysdig_event_type event_type);
const struct sysdig_event_info* sysdig_event2info(enum sysdig_event_type event_type);

#endif /* _PFRING_MOD_SYSDIG_H_ */
