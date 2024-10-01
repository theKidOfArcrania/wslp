#define _GNU_SOURCE
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

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

#define MAX_SIZE 0xA00000

static int create_temp_directory(char *outpath) {
  static char next_number = 0;
  char tmp[100];
  sprintf(tmp, "/tmp/image%d", next_number++);
  if (mkdir(tmp, 0700) != 0) {
    return -1;
  }

  strcpy(outpath, tmp);
  return 0;
}

void read_line(char *buf, size_t size) {
  while ( 1 ) {
    if ( !size )
      errx(1, "newline expected");
    if ( read(0, buf, 1uLL) != 1 )
      err(1, "read");
    if ( *buf == 10 )
      break;
    ++buf;
    --size;
  }

  *buf = 0;
}

int read_int() {
  char nptr[16] = "";
  read_line(nptr, 16LL);
  return atoi(nptr);
}

void readn(int fd, char *out, size_t nbytes) {
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

void vuln(int fd) {
  char buff[0x80];
  read(fd, buff, 0x100);
}

int load_elf() {
  size_t nbytes;
  char buf[0x1000];
  int fd;

  printf("elf len? ");
  fflush(stdout);
  nbytes = read_int();
  if (nbytes > MAX_SIZE) {
    errx(1, "too long");
  }
  printf("data? ");
  fflush(stdout);

  memset(buf, 0, 0x1000);
  fd = CHK(memfd_create, "x", MFD_CLOEXEC);
  while (nbytes) {
    size_t reading = 0x1000;
    if (reading > nbytes) {
      reading = nbytes;
    }
    readn(0, buf, reading);
    nbytes -= reading;
    if (reading != write(fd, buf, reading)) {
      errx(1, "short write");
    }
  }

  return fd;
}

void wait_for(int fd, const char *signal) {
  char buf[0x81];
  ssize_t reading;

  if (strlen(signal) + 1 > 0x80)
    _exit(1);
  reading = CHK(read, fd, buf, strlen(signal) + 1);
  if (reading != strlen(signal) + 1)
    _exit(1);
  if (strcmp(signal, buf))
    _exit(1);
}

void write_proc(unsigned int pid, const char *file, const char *str) {
  char path[64] = {0};
  int fd;
  int written = strlen(str);

  snprintf(path, 64, "/proc/%d/%s", pid, file);

  fd = CHK(open, path, O_WRONLY);
  if (written != write(fd, str, written)) {
    err(1, "write");
  }
  close(fd);
}

int child_proc(void *arg) {
  longjmp(*(jmp_buf*)arg, 1);
}

pid_t new_proc() {
  void *stack;
  pid_t ret;
  stack = aligned_alloc(0x10, 0x1000);

  jmp_buf env;
  if (setjmp(env) != 0) {
    // Return from child proccess
    free(stack);
    return 0;
  }

  ret = CHK(clone, child_proc, stack + 0x1000, CLONE_NEWNS |
      CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER |
      CLONE_NEWPID | SIGCHLD, &env);

  free(stack);
  return ret;
}


void start_sandbox(char *sandbox_path) {
  int fds[2];
  int wstatus;
  char cmd[200];
  pid_t child, child2;

  child = CHK(fork);
  if (!child) {
    CHK(socketpair, AF_UNIX, SOCK_STREAM, 0, fds);

    // Before unsharing user namespace, lets make sure that we have a separate
    // mount namespace!
    CHK(unshare, CLONE_NEWNS);
    CHK(mount, "none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    CHK(chdir, sandbox_path);
    CHK(mkdir, "./proc", 0755);
    CHK(mount, "/proc", "./proc", NULL, MS_BIND, NULL);

    CHK(syscall, SYS_pivot_root, ".", ".");
    CHK(umount2, ".", MNT_DETACH);
    CHK(chdir, "/");
    CHK(mkdir, "/mnt", 0555);

    // Now we create new user namespace with everything separated
    child2 = new_proc();
    if (!child2) {
      int elf;
      const char *argv[2];

      CHK(mount, "none", "/proc", "proc", 0, NULL);

      close(fds[0]);
      write(fds[1], "1", 2);
      wait_for(fds[1], "2");

      puts("Please send me an init ELF.");
      elf = load_elf();

      CHK(setresgid, 1, 1, 1);
      CHK(setresuid, 1, 1, 1);
      write(fds[1], "3", 2);
      close(fds[1]);

      argv[0] = "init";
      argv[1] = NULL;
      execveat(elf, "", (char**)argv, NULL, AT_EMPTY_PATH);
      err(1, "execveat");
    }

    close(fds[1]);
    wait_for(fds[0], "1");
    write_proc(child2, "uid_map", "1 1 1");
    write_proc(child2, "gid_map", "1 1 1");
    write(fds[0], "2", 2);
    wait_for(fds[0], "3");
    close(fds[0]);
    _exit(0);
  }

  waitpid(child, &wstatus, 0);
}

void new_sandbox() {
  char sandbox_path[100] = "";
  create_temp_directory(sandbox_path);
  CHK(mount, "none", sandbox_path, "tmpfs", 0, NULL);
  start_sandbox(sandbox_path);
}

void clone_sandbox() {
  char sandbox_path[100] = "";
  char cmd[500];
  int image_from;

  printf("Select number: ");
  fflush(stdout);
  image_from = read_int();

  mount("none", "/tmp/working", "tmpfs", 0, NULL);

  create_temp_directory(sandbox_path);

  snprintf(cmd, 200, "mount -t tmpfs none /tmp/working && "
      "cp -af /tmp/image%d/* /tmp/working &&"
      "mount --bind /tmp/working %s/ &&"
      "umount /tmp/working",
      image_from, sandbox_path);
  system(cmd);

  start_sandbox(sandbox_path);
}

void run_elf() {
  puts("TODO");
}

int maybe_mkdir(const char *dir, __mode_t mode) {
  if (mkdir(dir, mode) < 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

void init(char *rootfs) {
  struct rlimit rlim;

  // 5min timeout
  alarm(600);

  // Set some resource limitations
  rlim.rlim_cur = 5;
  rlim.rlim_max = 5;
  CHK(setrlimit, RLIMIT_CPU, &rlim);
  rlim.rlim_cur = MAX_SIZE;
  rlim.rlim_max = MAX_SIZE;
  CHK(setrlimit, RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = 100;
  rlim.rlim_max = 100;
  CHK(setrlimit, RLIMIT_NOFILE, &rlim);

  // Drop all supplemental groups
  CHK(setgroups, 0, NULL);

  // Prepare our rootfs. Note we must unshare the mount namespace before we
  // unshare the user namespace since if we do both at the same time all the
  // mountpoints will be marked with MNT_LOCKED, which prevents us from pivoting
  // root (annoying!)
  CHK(unshare, CLONE_NEWNS);
  CHK(mount, NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
  CHK(chdir, rootfs);

  // Prepare the /dev fs
  CHK(mount, "none", "/dev", "tmpfs", 0, NULL);
  CHK(symlink, "/proc/self/fd/0", "/dev/stdin");
  CHK(symlink, "/proc/self/fd/1", "/dev/stdout");
  CHK(symlink, "/proc/self/fd/2", "/dev/stderr");
  CHK(symlink, "/proc/self/fd", "/dev/fd");
  CHK(mknod, "/dev/null", 0666 | S_IFCHR, makedev(1, 3));
  CHK(chmod, "/dev/null", 0666);
  CHK(mknod, "/dev/zero", 0666 | S_IFCHR, makedev(1, 5));
  CHK(chmod, "/dev/zero", 0666);
  CHK(mknod, "/dev/full", 0666 | S_IFCHR, makedev(1, 7));
  CHK(chmod, "/dev/full", 0666);
  CHK(maybe_mkdir, "./dev", 0666);
  CHK(mount, "/dev", "./dev", NULL, MS_BIND, NULL);

  // Change to our new root
  CHK(syscall, SYS_pivot_root, ".", ".");
  CHK(umount2, ".", MNT_DETACH);
  CHK(chdir, "/");


  // Need external /proc directory first
  CHK(mount, "none", "/proc", "proc", 0, NULL);
  CHK(mount, "none", "/tmp", "tmpfs", 0, NULL);
  CHK(chmod, "/tmp", 0777 | S_ISVTX);
  CHK(mkdir, "/tmp/working", 0555);
}

int main(int argc, char **argv) {
  int fds[2];
  int wstatus;
  pid_t child;

  if (argc < 2) {
    fputs("Usage: containerd ROOTFS", stderr);
    return 2;
  }

  if (getuid()) {
    fputs("run me as root\n", stderr);
    return 1;
  }

  if (fork() == 0) {
    CHK(setresgid, 1001, 1001, 1001);
    CHK(setresuid, 1001, 1001, 1001);
    CHK(prctl, PR_SET_DUMPABLE, 1); // Since we need to access our own procfs
    sleep(300);
    _exit(0);
  }

  init(argv[1]);

  // Ensure that we are in a user namespace that will not give the user any
  // infra access even if they pwn this entire process.
  CHK(socketpair, AF_UNIX, SOCK_STREAM, 0, fds);
  child = new_proc();
  if (child) {
    sigset_t sigs;
    int num;

    CHK(sigemptyset, &sigs);
    CHK(sigaddset, &sigs, SIGALRM);
    CHK(sigaddset, &sigs, SIGCHLD);
    CHK(sigprocmask, SIG_BLOCK, &sigs, NULL);

    close(fds[1]);
    wait_for(fds[0], "1");
    write_proc(child, "setgroups", "deny");
    write_proc(child, "uid_map", "0 1000 2");
    write_proc(child, "gid_map", "0 1000 2");
    write(fds[0], "2", 2);
    wait_for(fds[0], "3");

    if (fork() == 0) {
      CHK(setresgid, 1001, 1001, 1001);
      CHK(setresuid, 1001, 1001, 1001);
      vuln(fds[0]);
      _exit(0);
    }

    close(fds[0]);
    CHK(sigwait, &sigs, &num);
    _exit(0);
  }

  close(fds[0]);
  write(fds[1], "1", 2);
  wait_for(fds[1], "2");
  write(fds[1], "3", 2);

  // We need another proc fs on top of our outer proc namespace one
  CHK(mount, "none", "/proc", "proc", 0, NULL);

  // Drop all perms
  CHK(setresgid, 0, 0, 0);
  CHK(setresuid, 0, 0, 1);
  CHK(prctl, PR_SET_DUMPABLE, 1); // Since we need to access our own procfs

  puts("An old namespace challenge (revised) by popular demand!");
  for(;;) {
    printf("What would you like to do?\n"
        "1) Start Sandbox\n"
        "2) Clone Sandbox\n"
        "3) Run ELF\n"
        "4) Exit\n> ");
    fflush(stdout);
    switch (read_int()) {
      case 1:
        new_sandbox();
        break;
      case 2:
        clone_sandbox();
        break;
      case 3:
        run_elf();
        break;
      default:
        puts("Bye");
        _exit(0);
    }
  }
}
