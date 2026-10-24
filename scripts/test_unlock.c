/* Тест разблокировки: open -> lock -> unlock тем же паролем */
#include "vault.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    plat_init();
    const char *dir = "/tmp/vunlock-t/v";
    const char *pass = "pass-12345678";

    fv_vault *v = NULL;
    int rc = fv_vault_open(&v, dir, pass);
    printf("open: %d (%s)\n", rc, fv_strerror(rc));
    if (rc != FV_OK) return 1;

    fv_vault_lock(v);
    printf("locked: %d\n", fv_vault_is_locked(v));

    rc = fv_vault_unlock(v, pass);
    printf("unlock: %d (%s)\n", rc, fv_strerror(rc));
    if (rc != FV_OK) { fv_vault_free(v); return 1; }

    rc = fv_vault_mkdir(v, "/ok-after-unlock");
    printf("mkdir after unlock: %d (%s)\n", rc, fv_strerror(rc));
    fv_vault_free(v);
    return rc;
}
