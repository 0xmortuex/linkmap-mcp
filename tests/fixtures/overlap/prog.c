/* Enough code to run past 0x1010, plus constant data pinned at 0x1010. */
const char message[] = "overlapping";
int _start(int a, int b) {
    int s = 0;
    for (int i = 0; i < a; i++) s += b * i + message[i % 11];
    return s;
}
