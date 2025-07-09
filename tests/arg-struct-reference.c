#include <stdio.h>

struct Point {
    int x;
    int y;
};

int print_point(struct Point* p) {
    printf("Point with address %p : `(%d, %d)\n",p,  p->x, p->y);
    return 0; 
}

int main() {
    struct Point pt = {10, 20};
    print_point(&pt);
    return 0;
}

