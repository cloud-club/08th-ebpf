#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE 1024 * 1024 * 10 // 10MB

int main() {
    int a, b;
    scanf("%d %d", &a, &b);

    volatile char arr[ARRAY_SIZE];
    memset((void*)arr, 0, ARRAY_SIZE);

    printf("%d", a + b);

    return 0;
}
