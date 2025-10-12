#include <stdio.h>

int main() {
    int a, b;
    scanf("%d %d", &a, &b);

    int *ptr = NULL;
    printf("%d", *ptr);

    printf("%d", a + b);

    return 0;
}
