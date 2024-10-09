#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define CHK(fn, args...) ({ \
    int64_t __res = fn(args); \
    if (__res == -1) { \
      err(1, "%s: %d: %s", __FILE__, __LINE__, #fn); \
    } \
    __res; \
  })

struct multiplex_addr {
  uint64_t key_lower;
  uint64_t key_upper;
  uint64_t port;
  uint64_t port_key;
};

struct sockaddr_in SERVER_ADDR;

int connect_mpa(const struct multiplex_addr *addr) {
  int fd = CHK(socket, AF_INET, SOCK_STREAM, 0);
  CHK(connect, fd, (struct sockaddr*)&SERVER_ADDR, sizeof(SERVER_ADDR));

  if (sizeof(*addr) != CHK(write, fd, addr, sizeof(*addr))) {
    errx(1, "short write");
  }

  return fd;
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

int maybe_mkdir(const char *dir, __mode_t mode) {
  if (mkdir(dir, mode) < 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s ADDRESS\n", program_invocation_short_name);
    return 2;
  }

  CHK(setresuid, 0, 0, 0);
  CHK(setresgid, 0, 0, 0);

  if (!strcmp(argv[1], "update")) {
    // Make sure my systems are up-to-date always lol
    return system("/usr/bin/apt-get update && /usr/bin/apt-get upgrade -y");
  }

  memset(&SERVER_ADDR, 0, sizeof(SERVER_ADDR));
  CHK(inet_aton, "10.69.0.1", &SERVER_ADDR.sin_addr);
  SERVER_ADDR.sin_port = htons(31337);
  SERVER_ADDR.sin_family = AF_INET;

  struct multiplex_addr mpa;
  if (sscanf(argv[1],"%lx:%lx:%lx:%lx", &mpa.key_lower,
      &mpa.key_upper, &mpa.port, &mpa.port_key) != 4) {
    puts("Invalid address format!");
    return 2;
  }

  CHK(maybe_mkdir, "/home/ctf/disk", 0755);
  if (CHK(system, "/bin/mount -o ro /home/ctf/disk.img /home/ctf/disk/") != 0) {
    errx(1, "mount failed");
  }

  int server = connect_mpa(&mpa);
  for(;;) {
    struct multiplex_addr client_mpa;
    readn(server, &client_mpa, sizeof(client_mpa));

    int client = connect_mpa(&client_mpa);
    if (!CHK(fork)) {
      CHK(dup2, client, 0);
      CHK(dup2, client, 1);
      CHK(dup2, client, 2);
      close(client);
      close(server);
      CHK(execl, "/home/ctf/containerd", "containerd", "/home/ctf/disk/");
      abort();
    }
    close(client);
  }
}
