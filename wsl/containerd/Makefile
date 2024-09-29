CFLAGS=-fstack-protector-all -fPIC
containerd: main.o
	$(CC) -static-pie -o $@ $^

clean:
	rm containerd *.o
