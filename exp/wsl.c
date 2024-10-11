#include <err.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>
#include "vm_sockets.h"

struct WslMessage2 {
  char myst1[24];
  uint32_t prog_offset;
  uint32_t cwd_offset;
  uint32_t arg_offset;
  uint32_t args;
  uint32_t env_offset;
  uint32_t myst2;
  uint8_t myst3;
};

struct WslMessageHeader {
  uint32_t msg_type;
  uint32_t msg_len;
  uint32_t const_1;
  uint32_t vsock_port;
};

struct WslMessage {
  struct WslMessageHeader hdr;
  struct WslMessage2 body;
};


#define CHK(fn, args...) ({ \
    int64_t __res = fn(args); \
    if (__res == -1) { \
      err(1, "%s: %d: %s", __FILE__, __LINE__, #fn); \
    } \
    __res; \
  })

#define WAIT_FDS 4

void writen(int fd, const void *in, size_t nbytes) {
  while (nbytes) {
    ssize_t n;
    n = CHK(write, fd, in, nbytes);
    nbytes -= n;
    in += n;
    if (!n) {
      errx(1, "short write");
    }
  }
}

void readn(int fd, void *out, size_t nbytes) {
  while (nbytes) {
    ssize_t n;
    n = CHK(read, fd, out, nbytes);
    nbytes -= n;
    out += n;
    if (!n) {
      errx(1, "short read");
    }
  }
}

enum control_msg_type {
  CONTROL_EXIT = 9,
  CONTROL_SET_WIDTH,
  CONTROL_START,
};

struct control_header {
  uint32_t msg_type;
  uint32_t msg_len;
  uint32_t myst;
};

union control_body {
  uint32_t exit;
  struct {
    uint16_t rows;
    uint16_t cols;
  } set_width;
  char start[20];
};


int exec_wsl(const char *interop_path, const char *cwd, const char *prog, int argc, const char **argv, const char **envp) {
  struct sockaddr_vm vm_addr;
  socklen_t vm_addr_len = sizeof(vm_addr);
  memset(&vm_addr, 0, sizeof(vm_addr));
  vm_addr.svm_family = AF_VSOCK;
  vm_addr.svm_cid = VMADDR_CID_ANY;
  vm_addr.svm_port = VMADDR_PORT_ANY;

  struct sockaddr_un interop_addr;
  memset(&interop_addr, 0, sizeof(interop_addr));
  interop_addr.sun_family = AF_UNIX;
  strncpy(interop_addr.sun_path, interop_path, sizeof(interop_addr.sun_path));

  int comm = CHK(socket, AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);

  CHK(bind, comm, (struct sockaddr*)&vm_addr, vm_addr_len);
  CHK(listen, comm, 4);
  CHK(getsockname, comm, (struct sockaddr*)&vm_addr, &vm_addr_len);

  // Send request to open process
  int interop = CHK(socket, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
  CHK(connect, interop, (struct sockaddr*)&interop_addr, sizeof(interop_addr));

  struct WslMessage header;
  memset(&header, 0, sizeof(header));
  header.hdr.msg_type = 8;
  header.hdr.msg_len = sizeof(struct WslMessage2);
  header.hdr.const_1 = 1;
  header.hdr.vsock_port = vm_addr.svm_port;
  header.body.args = argc;
  header.body.prog_offset = header.hdr.msg_len;
  header.hdr.msg_len += strlen(prog) + 1;
  header.body.cwd_offset = header.hdr.msg_len;
  header.hdr.msg_len += strlen(cwd) + 1;
  header.body.env_offset = header.hdr.msg_len;
  for (int i = 0; envp[i]; i++) {
    header.hdr.msg_len += strlen(envp[i]) + 1;
  }
  header.hdr.msg_len++;
  header.body.arg_offset = header.hdr.msg_len;
  for (int i = 0; i < argc; i++) {
    header.hdr.msg_len += strlen(argv[i]) + 1;
  }
  header.hdr.msg_len += sizeof(struct WslMessageHeader);

  struct WslMessage *msg = calloc(1, header.hdr.msg_len);
  memcpy(msg, &header, sizeof(header));
  char *off = (char*)&msg->body;
  strcpy(off + header.body.cwd_offset, cwd);
  strcpy(off + header.body.prog_offset, prog);

  char *ptr = off + header.body.arg_offset;
  for (int i = 0; i < argc; i++) {
    strcpy(ptr, argv[i]);
    ptr += strlen(argv[i]) + 1;
  }

  ptr = off + header.body.arg_offset;
  for (int i = 0; envp[i]; i++) {
    strcpy(ptr, envp[i]);
    ptr += strlen(envp[i]) + 1;
  }

  writen(interop, msg, msg->hdr.msg_len);
  free(msg);

  // Accept comm sockets
  int fin = CHK(accept, comm, (struct sockaddr*)&vm_addr, &vm_addr_len);
  int fout = CHK(accept, comm, (struct sockaddr*)&vm_addr, &vm_addr_len);
  int ferr = CHK(accept, comm, (struct sockaddr*)&vm_addr, &vm_addr_len);
  int fmyst = CHK(accept, comm, (struct sockaddr*)&vm_addr, &vm_addr_len);

  close(comm);
  close(interop);

  int write_to[WAIT_FDS] = { fin, 1, 2, -1 };

  struct pollfd polls[WAIT_FDS] = {
    {
      .fd = 0,
      .events = POLLIN,
    },
    {
      .fd = fout,
      .events = POLLIN,
    },
    {
      .fd = ferr,
      .events = POLLIN,
    },
    {
      .fd = fmyst,
      .events = POLLIN,
    },
  };

  char buff[0x1000];
  int exit_code = 0;
  for (;;) {
    CHK(poll, polls, WAIT_FDS, -1);
    for (int i = 0; i < WAIT_FDS; i++) {
      if (polls[i].revents & POLLIN) {
        if (polls[i].fd == fmyst) {
          struct control_header hdr;
          union control_body body;
          readn(fmyst, &hdr, sizeof(hdr));
          readn(fmyst, &body, MIN(sizeof(body), hdr.msg_len - sizeof(hdr)));

          switch (hdr.msg_type) {
            case CONTROL_START:
            case CONTROL_SET_WIDTH:
              break;
            case CONTROL_EXIT:
              close(fmyst);
              polls[i].fd = -1;
              exit_code = body.exit;
              break;
            default:
              fprintf(stderr, "Got control message %d", hdr.msg_type);
          }
        } else {
          polls[i].revents = 0;
          int len = CHK(read, polls[i].fd, buff, sizeof(buff));
          if (len == 0) {
            close(polls[i].fd);
            polls[i].fd = -1;
          }

          writen(write_to[i], buff, len);
        }
      }

    }
    if (polls[1].fd == -1 && polls[2].fd == -1 && polls[3].fd == -1) {
      break;
    }
  }

  return exit_code;
}

int exec_debian() {
  const char *prog = "C:\\Users\\ctf\\AppData\\Local\\Microsoft\\WindowsApps\\debian.exe";
  const char *argv[] = {"debian.exe"};
  //const char *prog = "C:\\Windows\\System32\\cmd.exe";
  //const char *argv[] = {"cmd.exe"};
  const char *envp[] = {NULL};

  const char *interop = getenv("WSL_INTEROP");
  if (interop == NULL) {
    interop = "/run/WSL/1_interop";
  }
  return exec_wsl(interop, "C:\\", prog, 1, argv, envp);
}
