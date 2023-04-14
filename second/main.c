#include <stdio.h>
#include "arg_handler.h"

int main(int argc, char *argv[]) {
    argument_t *arguments = parse_arguments(argc, argv);
    return 0;
}
