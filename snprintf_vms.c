#include <stdio.h>
#include <stdarg.h>

int snprintf_vms(char *str, size_t len, const char *fmt, ...)
{
   va_list ap;
   int n;

   va_start(ap, fmt);
   n = vsprintf(str, fmt, ap);
   va_end(ap);
   return n;
}
