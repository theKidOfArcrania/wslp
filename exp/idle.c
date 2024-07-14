#include <unistd.h>
#include <sys/wait.h>

int main() {
  for(;;) {
    if (wait(NULL) < 0) {
      sleep(1);
    }
  }
}
