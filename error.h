#include <errno.h>
 
#define ERR_ITEM(error_code) \
  { error_code, #error_code }
 
struct error_table {
  int code;
  char str[16];
} err_tbl[] = {
  ERR_ITEM(EPERM),
  ERR_ITEM(ENOENT),
  ERR_ITEM(ESRCH),
  ERR_ITEM(EINTR),
  ERR_ITEM(EIO),
  ERR_ITEM(ENXIO),
  ERR_ITEM(E2BIG),
  ERR_ITEM(ENOEXEC)
};
