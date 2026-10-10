AS=gcc
CFLAGS=-m32 -nostdlib
OBJCOPY=objcopy

all: shellcode.o shellcode.bin

SOURCE=shellcode.S

%.bin: %.o
	$(OBJCOPY) -j .text -O binary $< $@

shellcode.o: $(SOURCE)
	$(AS) $(CFLAGS) -o $@ $^

clean:
	-rm shellcode.o shellcode.bin
