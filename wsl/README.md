# wslp-wsl

This is the portion of the code that runs on the WSL instance. The runner is
a setuid-root binary that will run on start up. It connects to the host
partition's multiplex socket which will then eventually to your device.
