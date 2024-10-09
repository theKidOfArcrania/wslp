CFLAGS=-fstack-protector-all -fPIC
runner: runner.o
	$(CC) -static-pie -o $@ $^

clean:
	rm runner *.o
