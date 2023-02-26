.DEFAULT_GOAL := bpfelf

TARGET := trace.c

clean:
	-$(RM) bpfelf

bpfelf: clean
	clang -O2 -g -Wall  -emit-llvm -c trace.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o bpfelf


debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe