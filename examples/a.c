#include<stdio.h>
#include<unistd.h>
int main()
{
    char a[11];
    printf("what is your name?\n");
    scanf("%10s", a);
    printf("hello, %s", a);
    char b[0x10];
    printf("what do you want to do?\n");
    read(0, b, 0x10);
    printf("yes, you want to do %s\n", b);
    return 0;
}