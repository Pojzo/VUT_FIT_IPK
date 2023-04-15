#include <stdio.h>
#include "arg_handler.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
    // parse the arguments from command line
    argument_t *arguments = parse_arguments(argc, argv);

    // run the sniffer using the parsed arguments
    return run_sniffer(arguments);
}
