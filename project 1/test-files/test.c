#include <stdio.h>

char low = -1;

int a = 10;
int b = 42;
static int c = 1024;
int d;

int e  __attribute__((section(".secret"))) = 'a';

int f __attribute__((section(".secret2")));

int g = -21;

extern int w;

int _y = 1;

const int z = 999;

int veryveryveryverylongname = 1234567890;

long long big = -9876543210;

char onebyte = 1;
short twobyte = 2;
long long eightbyte = 8;
char *x = "Hello world!";
void *ptr = NULL;
double db = 12.34;

int main() {
  printf("a=%d, b=%d c=%d d=%d e=%d f=%d w=%d\n", a, b, c, d, e, f, w);
  return 0;
}