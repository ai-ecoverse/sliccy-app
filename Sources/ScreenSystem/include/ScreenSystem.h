#ifndef SLICCY_SCREEN_SYSTEM_H
#define SLICCY_SCREEN_SYSTEM_H
#include <sys/types.h>
#include <stddef.h>
#include <Security/Security.h>
OSStatus sliccy_screen_dynamic_status(SecCodeRef code, uint32_t *status);
// All received ancillary data is refused; delivered rights are closed first.
ssize_t sliccy_screen_recv(int fd, void *buffer, size_t size);
// Starts suspended with only stdio and bootstrap FD3 inherited. Caller must reap.
int sliccy_screen_spawn(const char *executable, char *const argv[], char *const env[], pid_t *pid, int *input, int *output, int *bootstrap);
#endif
