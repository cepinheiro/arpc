CC      = /usr/bin/gcc
FLAGS   = -O2 -o
OBJ     = arpc
VERSION = 1.3

all: debug

debug:
	@echo  ""
	@echo -n "Compiling AISL RPC SCANNER v$(VERSION)... "
	@$(CC) -D_DEBUG_ $(FLAGS) $(OBJ) arpc.c
	@echo "Done."

non-debug:
	@echo  ""
	@echo -n "Compiling AISL RPC SCANNER v$(VERSION)... "
	@$(CC) $(FLAGS) $(OBJ) arpc.c
	@echo  "Done." 
	
install:
	@echo  ""
	@echo -n "Instaling rpcscan in /usr/sbin..."
	@/bin/sh -c "/usr/bin/install arpc /usr/sbin"
	@echo  "Done!"
	
clean:
	@echo  ""
	@echo -n "Removing AISL RPC SCANNER v$(VERSION)... "
	@rm -r /usr/sbin/arpc
	@rm -r ./arpc
	@echo "Done."
