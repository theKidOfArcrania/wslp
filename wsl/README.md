# wslp-wsl

This is the portion of the code that runs on the WSL instance. There are two
runners that you can use to test your exploits. Using the command:
`sudo socat TCP-LISTEN:1024,fork EXEC:./run.sh` is the easiest way to test
your exploit.

You can also run `./run_shared.sh "pbctf{fake_flag}"` and then pass in the
IP/port number on one line in standard input to have the runner connect to that
specific TCP port with the containerd CLI. Note that the two approaches may
result in slightly different file descriptors so be aware of that!

The lather approach is the one that we actually use for our infrastructure.
