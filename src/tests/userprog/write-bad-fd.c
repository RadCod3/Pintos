/* Tries to write to an invalid fd,
   which must either fail silently or terminate the process with
   exit code -1. */

#include <limits.h>
#include <syscall.h>
#include "tests/main.h"

void
test_main (void) 
{
  char buf = 123;
  write (0x01012342, &buf, 1);
  printf ("write(0x01012342, &buf, 1) returned\n");
  write (7, &buf, 1);
  printf ("write(7, &buf, 1) returned\n");
  write (2546, &buf, 1);
  printf ("write(2546, &buf, 1) returned\n");
  write (-5, &buf, 1);
  printf ("write(-5, &buf, 1) returned\n");
  write (-8192, &buf, 1);
  write (INT_MIN + 1, &buf, 1);
  write (INT_MAX - 1, &buf, 1);
}
