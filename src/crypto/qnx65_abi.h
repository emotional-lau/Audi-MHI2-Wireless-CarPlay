#ifndef P0916_QNX65_ABI_H
#define P0916_QNX65_ABI_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WCP_HOST_TEST
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define QNX_EAGAIN EAGAIN
#define QNX_EWOULDBLOCK EWOULDBLOCK
#define QNX_EINTR EINTR
#define QNX_ENOENT ENOENT
#define QNX_EBADF EBADF
#define QNX_EBUSY EBUSY
#define QNX_EEXIST EEXIST
#define QNX_EINVAL EINVAL
#define QNX_ENOMEM ENOMEM
#define QNX_ENOSPC ENOSPC
#define QNX_ENOSYS ENOSYS
#define QNX_EIO EIO
#define QNX_ECANCELED ECANCELED
#ifdef EOVERFLOW
#define QNX_EOVERFLOW EOVERFLOW
#else
#define QNX_EOVERFLOW ERANGE
#endif
#define QNX_SHUT_RDWR 2
#define qnx_errno errno
#else

/* Verified QNX 6.5.0 ARM32 (Neutrino) constants from P0916 MU0916 ELF binaries. */
#define QNX_RTLD_DEFAULT ((void *)(uintptr_t)-2)
#define QNX_RTLD_NEXT ((void *)(uintptr_t)-3)

#define QNX_CLOCK_REALTIME 0
#define QNX_CLOCK_MONOTONIC 2

#define QNX_ENOENT 2
#define QNX_EINTR 4
#define QNX_EIO 5
#define QNX_EBADF 9
#define QNX_EAGAIN 11
#define QNX_EWOULDBLOCK 11
#define QNX_ENOMEM 12
#define QNX_EBUSY 16
#define QNX_EEXIST 17
#define QNX_EINVAL 22
#define QNX_ENOSPC 28
#define QNX_ECANCELED 47
#define QNX_EOVERFLOW 79
#define QNX_ENOSYS 89

#define QNX_AF_INET 2
#define QNX_AF_INET6 24
#define QNX_SOCK_STREAM 1
#define QNX_SOCK_DGRAM 2
#define QNX_SOL_SOCKET 0xffff
#define QNX_SO_REUSEADDR 0x0004
#define QNX_SO_SNDBUF 0x1001
#define QNX_SO_RCVBUF 0x1002
#define QNX_SO_TYPE 0x1008
#define QNX_SHUT_RDWR 2
#define QNX_POLLIN 0x0001
#define QNX_POLLOUT 0x0002

#define QNX_PTHREAD_MUTEX_INITIALIZER { (int)0x80000000, 0xffffffffU }
#define QNX_PTHREAD_ONCE_INIT { 0, { (int)0x80000000, 0xffffffffU } }

typedef struct {
    int __count;
    unsigned __owner;
} qnx_pthread_mutex_t;

typedef struct {
    int __once;
    qnx_pthread_mutex_t __mutex;
} qnx_pthread_once_t;

typedef uint32_t qnx_pthread_t;
typedef uint32_t qnx_socklen_t;
typedef uint16_t qnx_sa_family_t;
typedef int32_t qnx_ssize_t;
typedef uint32_t qnx_mode_t;

struct qnx_timespec {
    int32_t tv_sec;
    int32_t tv_nsec;
};

struct qnx_sockaddr {
    uint8_t sa_len;
    uint8_t sa_family;
    char sa_data[14];
};

struct qnx_sockaddr_in {
    uint8_t sin_len;
    uint8_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
};

struct qnx_sockaddr_in6 {
    uint8_t sin6_len;
    uint8_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
    uint32_t sin6_scope_id;
};

struct qnx_iovec {
    void *iov_base;
    size_t iov_len;
};

struct qnx_pollfd {
    int fd;
    short events;
    short revents;
};

typedef struct qnx_FILE qnx_FILE;

/* Dynamic symbols resolved from QNX 6.5 libc.so.3 / libsocket.so.3 */
extern void *malloc(size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern void *realloc(void *ptr, size_t size);
extern void free(void *ptr);

extern void *memcpy(void *dst, const void *src, size_t n);
extern void *memmove(void *dst, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);
extern int memcmp(const void *s1, const void *s2, size_t n);
extern void *memchr(const void *s, int c, size_t n);

extern size_t strlen(const char *s);
extern int strcmp(const char *s1, const char *s2);
extern int strncmp(const char *s1, const char *s2, size_t n);
extern char *strcpy(char *dst, const char *src);
extern char *strncpy(char *dst, const char *src, size_t n);
extern char *strchr(const char *s, int c);
extern char *strstr(const char *haystack, const char *needle);
extern char *strdup(const char *s);

extern int snprintf(char *str, size_t size, const char *format, ...);
extern int vsnprintf(char *str, size_t size, const char *format, va_list ap);

extern qnx_FILE *fopen(const char *pathname, const char *mode);
extern size_t fread(void *ptr, size_t size, size_t nmemb, qnx_FILE *stream);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, qnx_FILE *stream);
extern int fflush(qnx_FILE *stream);
extern int fclose(qnx_FILE *stream);
extern int rename(const char *oldpath, const char *newpath);
extern int unlink(const char *pathname);
extern int mkdir(const char *pathname, qnx_mode_t mode);
extern int chmod(const char *pathname, qnx_mode_t mode);

extern int close(int fd);
extern qnx_ssize_t read(int fd, void *buf, size_t count);
extern qnx_ssize_t write(int fd, const void *buf, size_t count);
extern qnx_ssize_t recv(int sockfd, void *buf, size_t len, int flags);
extern qnx_ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                            struct qnx_sockaddr *src_addr, qnx_socklen_t *addrlen);
extern qnx_ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                          const struct qnx_sockaddr *dest_addr, qnx_socklen_t addrlen);
extern int getsockopt(int sockfd, int level, int optname, void *optval, qnx_socklen_t *optlen);
extern int setsockopt(int sockfd, int level, int optname, const void *optval, qnx_socklen_t optlen);
extern int bind(int sockfd, const struct qnx_sockaddr *addr, qnx_socklen_t addrlen);
extern int shutdown(int sockfd, int how);
extern int socket(int domain, int type, int protocol);
extern int poll(struct qnx_pollfd *fds, unsigned int nfds, int timeout);
extern unsigned int if_nametoindex(const char *ifname);

extern char *getenv(const char *name);
extern int getpid(void);
extern int usleep(unsigned int usec);
extern unsigned int sleep(unsigned int seconds);
extern int clock_gettime(int clk_id, struct qnx_timespec *tp);
extern int *__get_errno_ptr(void);
#define qnx_errno (*__get_errno_ptr())

extern void *dlsym(void *handle, const char *symbol);

extern int pthread_mutex_lock(qnx_pthread_mutex_t *mutex);
extern int pthread_mutex_unlock(qnx_pthread_mutex_t *mutex);
extern int pthread_once(qnx_pthread_once_t *once_control, void (*init_routine)(void));
extern int pthread_create(qnx_pthread_t *thread, const void *attr, void *(*start_routine)(void *), void *arg);
extern int pthread_detach(qnx_pthread_t thread);
extern int pthread_join(qnx_pthread_t thread, void **value_ptr);

static inline uint16_t qnx_htons(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}

static inline uint16_t qnx_ntohs(uint16_t v)
{
    return qnx_htons(v);
}

#endif /* WCP_HOST_TEST */

/* AirPlay / CoreFoundation OSStatus codes shared by stock 210.81 and HAP pairing. */
#define WCP_kNoErr 0
#define WCP_kParamErr (-6705)
#define WCP_kNoMemoryErr (-6728)
#define WCP_kUnknownErr (-6700)
#define WCP_kBadReferenceErr (-6707)
#define WCP_kNotFoundErr (-6727)
#define WCP_kStateErr (-6709)
#define WCP_kSizeErr (-6743)
#define WCP_kConnectionErr (-6753)
#define WCP_kAuthenticationErr (-6754)
#define WCP_kUnsupportedErr (-6735)
#define WCP_kMalformedErr (-6762)

#endif /* P0916_QNX65_ABI_H */
