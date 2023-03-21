.PHONY: all module

all: exp

exp: exp.c
	gcc exp.c -o exp -static -no-pie

module:
	make -C vuln_module
