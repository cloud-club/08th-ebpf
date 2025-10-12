#include <stdio.h>

int main() {
    int a, b;
    scanf("%d %d", &a, &b);

    volatile long long sum = 0;
    for (long long i = 0; i < 10000000000; i++) {
        sum += 1;
    }

    printf("%d", a + b);
    printf("\n%lld", sum);

    return 0;
}