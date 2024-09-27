#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

// tiny utility that makes the first arg as stdin then execs on
// this is so we can run cpio without a shell redirection `<` in hyperfine

int main(int argc, char* argv[]) {
    //           0          1       2
    // args are ["asstdin", infile, cmd, ...] 
    if (argc < 3) {
        return EXIT_FAILURE;
    }
    int ret = close(0);
    assert(ret == 0);
    int fd = open(argv[1], O_RDONLY);
    assert(fd == 0);
    execvp(argv[2], &argv[2]);
    assert(0);
}
