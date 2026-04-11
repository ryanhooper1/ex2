CFLAGS = -Wall -Werror -g -fdiagnostics-color=always

all: firewallSetup

firewallSetup: firewallSetup.o
	$(CC) $(CFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o firewallSetup
