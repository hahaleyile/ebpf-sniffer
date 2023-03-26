build:
	clang -O2 -g -target bpf -c xdppass.bpf.c -o xdppass.o
	gcc -O2 xdpclient.c -o xdpclient -lbpf 

