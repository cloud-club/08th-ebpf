#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For sleep

#define MEMORY_SIZE (10 * 1024 * 1024) // 10 MB

int main() {
    char *memory = (char *)malloc(MEMORY_SIZE);
    if (memory == NULL) {
        return 1;
    }

    memset(memory, 0, MEMORY_SIZE);

    int a, b;
    scanf("%d %d", &a, &b);
    printf("%d", a + b);

    free(memory);

    return 0;
}
