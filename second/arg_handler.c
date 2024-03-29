#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arg_handler.h"

// print error message, free arguments and return with given exit code
static void *return_free(arguments_t *arguments, const char *msg) {
    fprintf(stderr, msg);
    arguments_free(arguments);
    return NULL;
}

// free arguments->interface if it's defined and the pointer itself
void arguments_free(arguments_t *arguments) {
    if (arguments->interface != NULL) {
        free(arguments->interface);
    }
    free(arguments);
}

// return true if all digits in 'value' are numbers
static bool is_number(const char *value) {
    for (size_t i = 0; i < strlen(value); i++) {
        if (value[i] < '0' || value[i] > '9') {
            return false;
        }
    }
    return true;
}

// return true if value starts with -
static inline bool is_option(const char* value) {
    return strncmp(value, "-", 1) == 0;
}

// return true if only interface and no other arguments were supplied
static bool check_interface_only(arguments_t *a) {
    bool result = a->tcp || a->udp || a->icmp4 || a->icmp6 || a->igmp || a->mld || a->port_specified || a->n_packets_specified;

    // if result is true, that means that something other than interface was specified
    return !result;
}

// check arguments from command line and return pointer to arguments_t
arguments_t *parse_arguments(int argc, char *argv[]) {
    arguments_t *arguments = (arguments_t *) malloc(sizeof(arguments_t));
    // set default values for the parameters
    arguments->n_packets = 1; // default value for showing packets is 0
    arguments->port = 0; // port 0 means don't filter anything
    arguments->interface = NULL; 
    arguments->interface_only = true; // whenever there is another argument supplied, change this to false
                                      //

    arguments->tcp = false;
    arguments->udp = false;
    arguments->arp = false;
    arguments->ndp = false;
    arguments->icmp4 = false;
    arguments->icmp6 = false;
    arguments->igmp = false;
    arguments->mld = false;
    arguments->port_specified = false;
    arguments->n_packets_specified = false;

    for (int8_t i = 1; i < argc; i++) {
        const char *cur_arg = argv[i];
        if (strcmp(cur_arg, "--interface") == 0 || strcmp(cur_arg, "-i") == 0) {
            if (i + 1 < argc) {
                if (is_option(argv[i + 1])) continue;

                uint8_t value_len = strlen(argv[i + 1]);
                arguments->interface = (char *) malloc(value_len + 1);
                strcpy(arguments->interface, argv[i + 1]);
                arguments->interface[value_len] = '\0';
                i++;
            }
        }

        else if (strcmp(cur_arg, "-n") == 0) {
            if (i + 1 < argc) {
                if (is_option(argv[i + 1])) continue;
                if (!is_number(argv[i + 1])) return return_free(arguments, "Number of packets must be a number\n");

                arguments->n_packets = (uint16_t) atoi(argv[i + 1]);
                arguments->n_packets_specified = true;
                i++;
            }
        }
        else if (strcmp(cur_arg, "-p") == 0) {
            if (i + 1 < argc) {
                if (is_option(argv[i + 1])) continue;
                if (!is_number(argv[i + 1])) return return_free(arguments, "Port must be a number\n");

                arguments->port = (uint16_t) atoi(argv[i + 1]);
                arguments->port_specified = true;
                i++;
            }
        }

        else if ((strcmp(cur_arg, "-t") == 0) || (strcmp(cur_arg, "--tcp") == 0)) {
            arguments->tcp = true;
        }
        else if ((strcmp(cur_arg, "-u") == 0) || (strcmp(cur_arg, "--udp") == 0)) {
            arguments->udp = true;
        }
        else if (strcmp(cur_arg, "--arp") == 0) {
            arguments->arp = true;
        }
        else if (strcmp(cur_arg, "--icmp4") == 0) {
            arguments->icmp4 = true;
        }
        else if (strcmp(cur_arg, "--icmp6") == 0) {
            arguments->icmp6 = true;
        }
        else if (strcmp(cur_arg, "--igmp") == 0) {
            arguments->igmp = true;
        }
        else if (strcmp(cur_arg, "--mld") == 0) {
            arguments->mld = true;
        }
        else if (strcmp(cur_arg, "--ndp") == 0) {
            arguments->ndp = true;
        }
        else {
            return return_free(arguments, "Invalid argument\n");
        }

    }
    arguments->interface_only = check_interface_only(arguments);
    // if not only interface was specified, we need to make sure that interface has a value
    if (!arguments->interface_only) {
        if (arguments->interface == NULL) {
            return return_free(arguments, "No interface was specified\n");
        }
    }
    return arguments;
}
