/* index.c */
#include "index.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IX_SERIAL_VERSION 1u
#define IX_MAX_NODES (4u * 1024u * 1024u)

void fv_index_init(fv_index *ix)
{
    ix->nodes = NULL;
    ix->count = ix->cap = 0;
    ix->next_id = 1;
}

void fv_index_free(fv_index *ix)
{
    if (!ix) return;
    free(ix->nodes);
    fv_index_init(ix);
}

static int index_grow(fv_index *ix)
{
    size_t nc = ix->cap ? ix->cap * 2 : 16;
    fv_node *nn = (fv_node *)realloc(ix->nodes, nc * sizeof(fv_node));
    if (!nn) return FV_ERR_NOMEM;
    ix->nodes = nn;
    ix->cap = nc;
    return FV_OK;
}

int fv_index_make_root(fv_index *ix)
{
    fv_index_init(ix);
    int rc = index_grow(ix);
    if (rc != FV_OK) return rc;
    fv_node *r = &ix->nodes[0];
    memset(r, 0, sizeof *r);
    r->id = 1;
    r->parent = 0;
    r->type = FV_NODE_DIR;
    r->name[0] = '\0';           /* имя корня не печатается никогда */
    ix->count = 1;
    ix->next_id = 2;
    return FV_OK;
}

/* ---------- имена и пути ---------- */

static int name_ok(const char *s, size_t l)
{
    if (l == 0 || l > FV_NAME_MAX) return 0;
    if (l == 1 && s[0] == '.') return 0;
    if (l == 2 && s[0] == '.' && s[1] == '.') return 0;
    for (size_t i = 0; i < l; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\') return 0;
    }
    return 1;
}

int fv_index_norm_path(const char *in, char *out, size_t outlen)
{
    if (!in || !out || outlen < 3) return FV_ERR_ARG;
    if (!*in) {
        strcpy(out, "/");
        return FV_OK;
    }

    size_t pos = 0;
    out[0] = '\0';
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *st = p;
        while (*p && *p != '/') p++;
        size_t l = (size_t)(p - st);

        if (l == 1 && st[0] == '.') continue;
        if (l == 2 && st[0] == '.' && st[1] == '.') {
            if (pos == 0) return FV_ERR_RANGE;      /* выше корня */
            while (pos && out[pos - 1] != '/') pos--;
            if (pos) pos--;                          /* убрать '/' хвостового компонента */
            out[pos] = '\0';
            continue;
        }
        if (!name_ok(st, l)) return FV_ERR_ARG;
        if (pos + 1 + l >= outlen) return FV_ERR_RANGE;
        out[pos++] = '/';
        memcpy(out + pos, st, l);
        pos += l;
        out[pos] = '\0';
    }
    if (pos == 0) {
        strcpy(out, "/");
        return FV_OK;
    }
    return FV_OK;
}

static const fv_node *find_child(const fv_index *ix, uint64_t parent,
                                 const char *name, size_t l)
{
    for (size_t i = 0; i < ix->count; i++) {
        const fv_node *n = &ix->nodes[i];
        if (n->parent == parent && strlen(n->name) == l && !memcmp(n->name, name, l))
            return n;
    }
    return NULL;
}

int fv_index_resolve_ex(const fv_index *ix, const char *path, fv_loc *loc)
{
    if (!ix || !path) return FV_ERR_ARG;
    char norm[FV_PATH_MAX];
    int rc = fv_index_norm_path(path, norm, sizeof norm);
    if (rc != FV_OK) return rc;

    if (loc) {
        loc->id = 0;
        loc->parent = 0;
        loc->name[0] = '\0';
    }
    if (!strcmp(norm, "/")) {
        if (loc) loc->id = 1;
        return FV_OK;
    }

    uint64_t cur = 1;
    const char *p = norm + 1;
    for (;;) {
        const char *q = strchr(p, '/');
        size_t l = q ? (size_t)(q - p) : strlen(p);
        const fv_node *ch = find_child(ix, cur, p, l);
        if (!ch) {
            if (loc && !q) {                         /* не хватает ровно последнего */
                loc->parent = cur;
                memcpy(loc->name, p, l);
                loc->name[l] = '\0';
            }
            return FV_ERR_NOTFOUND;
        }
        cur = ch->id;
        if (!q) break;
        p = q + 1;
    }
    if (loc) {
        const fv_node *n = fv_index_get(ix, cur);
        if (!n) return FV_ERR_NOTFOUND;
        loc->id = cur;
        loc->parent = n->parent;
        strcpy(loc->name, n->name);
    }
    return FV_OK;
}

int fv_index_resolve(const fv_index *ix, const char *path, uint64_t *id)
{
    fv_loc loc;
    int rc = fv_index_resolve_ex(ix, path, &loc);
    if (rc != FV_OK) return rc;
    if (!loc.id) return FV_ERR_NOTFOUND;
    if (id) *id = loc.id;
    return FV_OK;
}

/* ---------- доступ к узлам ---------- */

const fv_node *fv_index_get(const fv_index *ix, uint64_t id)
{
    if (!ix || id == 0) return NULL;
    for (size_t i = 0; i < ix->count; i++)
        if (ix->nodes[i].id == id) return &ix->nodes[i];
    return NULL;
}

fv_node *fv_index_node(fv_index *ix, uint64_t id)
{
    if (!ix || id == 0) return NULL;
    for (size_t i = 0; i < ix->count; i++)
        if (ix->nodes[i].id == id) return &ix->nodes[i];
    return NULL;
}

int fv_index_has_children(const fv_index *ix, uint64_t id)
{
    if (!ix) return 0;
    for (size_t i = 0; i < ix->count; i++)
        if (ix->nodes[i].parent == id) return 1;
    return 0;
}

uint64_t fv_index_add_node(fv_index *ix, uint64_t parent, const char *name,
                           uint8_t type, uint64_t mtime)
{
    if (!ix || !name) return 0;
    const fv_node *p = fv_index_get(ix, parent);
    if (!p || p->type != FV_NODE_DIR) return 0;
    size_t l = strlen(name);
    if (!name_ok(name, l)) return 0;
    if (find_child(ix, parent, name, l)) return 0;
    if (ix->count == ix->cap && index_grow(ix) != FV_OK) return 0;

    fv_node *n = &ix->nodes[ix->count++];
    memset(n, 0, sizeof *n);
    n->id = ix->next_id++;
    n->parent = parent;
    n->type = type;
    memcpy(n->name, name, l + 1);
    n->mtime = mtime;
    if (type == FV_NODE_FILE)
        snprintf(n->blob, sizeof n->blob, "%032x", 0);   /* заполнит вызывающий */
    return n->id;
}

void fv_index_remove_one(fv_index *ix, uint64_t id)
{
    if (!ix) return;
    for (size_t i = 0; i < ix->count; i++) {
        if (ix->nodes[i].id == id) {
            memmove(&ix->nodes[i], &ix->nodes[i + 1],
                    (ix->count - i - 1) * sizeof(fv_node));
            ix->count--;
            return;
        }
    }
}

int fv_index_collect_subtree(const fv_index *ix, uint64_t id,
                             fv_node **out, size_t *count)
{
    if (!ix || !out || !count) return FV_ERR_ARG;
    *out = NULL;
    *count = 0;
    const fv_node *root = fv_index_get(ix, id);
    if (!root) return FV_ERR_NOTFOUND;

    fv_node *arr = (fv_node *)malloc((ix->count ? ix->count : 1) * sizeof(fv_node));
    if (!arr) return FV_ERR_NOMEM;
    size_t n = 0;
    arr[n++] = *root;

    int added = 1;
    while (added) {
        added = 0;
        for (size_t i = 0; i < ix->count; i++) {
            int inside = 0;
            for (size_t k = 0; k < n; k++)
                if (arr[k].id == ix->nodes[i].parent) { inside = 1; break; }
            if (!inside) continue;
            int dup = 0;
            for (size_t k = 0; k < n; k++)
                if (arr[k].id == ix->nodes[i].id) { dup = 1; break; }
            if (!dup) {
                arr[n++] = ix->nodes[i];
                added = 1;
            }
        }
    }
    *out = arr;
    *count = n;
    return FV_OK;
}

void fv_index_remove_ids(fv_index *ix, const uint64_t *ids, size_t n)
{
    if (!ix || !ids) return;
    for (size_t i = 0; i < n; i++)
        fv_index_remove_one(ix, ids[i]);
}

void fv_index_restore_nodes(fv_index *ix, const fv_node *nodes, size_t n)
{
    if (!ix || !nodes) return;
    for (size_t i = 0; i < n; i++) {
        if (ix->count == ix->cap && index_grow(ix) != FV_OK) return;
        ix->nodes[ix->count++] = nodes[i];
    }
}

/* ---------- список детей ---------- */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int cmp_node(const void *a, const void *b)
{
    const fv_node *x = *(const fv_node * const *)a;
    const fv_node *y = *(const fv_node * const *)b;
    int dx = (x->type == FV_NODE_DIR);
    int dy = (y->type == FV_NODE_DIR);
    if (dx != dy) return dy - dx;                /* каталоги раньше файлов */
    return strcmp(x->name, y->name);
}

int fv_index_list(const fv_index *ix, uint64_t dir_id, fv_list_cb cb, void *ctx)
{
    if (!ix || !cb) return FV_ERR_ARG;
    const fv_node *d = fv_index_get(ix, dir_id);
    if (!d || d->type != FV_NODE_DIR) return FV_ERR_ARG;

    size_t n = 0;
    for (size_t i = 0; i < ix->count; i++)
        if (ix->nodes[i].parent == dir_id) n++;
    if (!n) return FV_OK;

    const fv_node **ptrs = (const fv_node **)malloc(n * sizeof *ptrs);
    if (!ptrs) return FV_ERR_NOMEM;
    size_t k = 0;
    for (size_t i = 0; i < ix->count; i++)
        if (ix->nodes[i].parent == dir_id) ptrs[k++] = &ix->nodes[i];
    qsort(ptrs, n, sizeof *ptrs, cmp_node);

    int stop = 0;
    for (size_t i = 0; i < n && !stop; i++)
        stop = (cb(ptrs[i], ctx) != 0);
    free(ptrs);
    return FV_OK;
}

/* ---------- сериализация ---------- */

int fv_index_serialize(const fv_index *ix, fv_buf *out)
{
    if (!ix || !out) return FV_ERR_ARG;
    if (ix->count > IX_MAX_NODES) return FV_ERR_RANGE;
    fv_buf_init(out);
    int rc;
    if ((rc = fv_buf_add_u32(out, IX_SERIAL_VERSION)) ||
        (rc = fv_buf_add_u32(out, (uint32_t)ix->count)) ||
        (rc = fv_buf_add_u64(out, ix->next_id)))
        return rc;

    for (size_t i = 0; i < ix->count; i++) {
        const fv_node *n = &ix->nodes[i];
        size_t nl = strlen(n->name);
        if (nl > FV_NAME_MAX) { fv_buf_free(out); return FV_ERR_RANGE; }
        if ((rc = fv_buf_add_u64(out, n->id)) ||
            (rc = fv_buf_add_u64(out, n->parent)) ||
            (rc = fv_buf_add_u8(out, n->type)) ||
            (rc = fv_buf_add_u8(out, (uint8_t)nl)) ||
            (rc = fv_buf_add(out, n->name, nl)))
            return rc;
        if (n->type == FV_NODE_FILE) {
            if ((rc = fv_buf_add(out, n->blob, 32)) ||
                (rc = fv_buf_add_u64(out, n->size)) ||
                (rc = fv_buf_add_u32(out, n->chunk_size)) ||
                (rc = fv_buf_add_u64(out, n->mtime)))
                return rc;
        }
    }
    return FV_OK;
}

int fv_index_deserialize(fv_index *ix, const uint8_t *p, size_t len)
{
    if (!ix || !p) return FV_ERR_ARG;
    fv_index_init(ix);

    size_t off = 0;
    if (len < 16) goto bad;
    uint32_t ver = fv_get_u32(p);           off += 4;
    uint32_t cnt = fv_get_u32(p + off);     off += 4;
    uint64_t nid = fv_get_u64(p + off);     off += 8;
    if (ver != IX_SERIAL_VERSION || cnt > IX_MAX_NODES) goto bad;
    if (cnt > (len - off) / 18 + 1) goto bad;    /* узел не может быть короче 18 байт */

    while (ix->cap < cnt) {
        if (index_grow(ix) != FV_OK) goto bad;
    }

    uint64_t max_id = 1;
    for (uint32_t i = 0; i < cnt; i++) {
        fv_node *n = &ix->nodes[ix->count];
        memset(n, 0, sizeof *n);
        if (len - off < 18) goto bad;
        n->id = fv_get_u64(p + off);         off += 8;
        n->parent = fv_get_u64(p + off);     off += 8;
        n->type = p[off++];
        uint8_t nl = p[off++];
        if (len - off < nl) goto bad;                /* nl <= 255 по типу */
        memcpy(n->name, p + off, nl);
        off += nl;
        if (nl && !name_ok(n->name, nl)) goto bad;
        if (nl == 0 && n->id != 1) goto bad;         /* без имени только корень */
        if (n->id == 0) goto bad;

        if (n->type == FV_NODE_FILE) {
            if (len - off < 32 + 8 + 4 + 8) goto bad;
            memcpy(n->blob, p + off, 32);        off += 32;
            n->blob[32] = '\0';
            n->size = fv_get_u64(p + off);       off += 8;
            n->chunk_size = fv_get_u32(p + off); off += 4;
            n->mtime = fv_get_u64(p + off);      off += 8;
            if (!n->chunk_size) goto bad;
        } else if (n->type != FV_NODE_DIR) {
            goto bad;
        }

        ix->count++;
        if (n->id > max_id) max_id = n->id;
    }
    if (off != len) goto bad;

    /* --- структурные проверки --- */

    /* ровно один корень: id==1, parent==0, каталог */
    {
        int roots = 0;
        for (size_t i = 0; i < ix->count; i++) {
            const fv_node *n = &ix->nodes[i];
            if (n->id == 1) {
                roots++;
                if (n->parent != 0 || n->type != FV_NODE_DIR) goto bad;
            } else if (n->parent == 0) {
                goto bad;
            }
        }
        if (roots != 1) goto bad;
    }

    /* уникальность id */
    {
        uint64_t *ids = (uint64_t *)malloc((ix->count ? ix->count : 1) * sizeof(uint64_t));
        if (!ids) goto bad;
        for (size_t i = 0; i < ix->count; i++) ids[i] = ix->nodes[i].id;
        qsort(ids, ix->count, sizeof(uint64_t), cmp_u64);
        int dup = 0;
        for (size_t i = 1; i < ix->count; i++)
            if (ids[i] == ids[i - 1]) { dup = 1; break; }
        free(ids);
        if (dup) goto bad;
    }

    /* parent существует, является каталогом; достижимость из корня (ловит циклы) */
    {
        uint8_t *mark = (uint8_t *)calloc(ix->count ? ix->count : 1, 1);
        if (!mark) goto bad;
        size_t marked = 0;
        for (size_t i = 0; i < ix->count; i++)
            if (ix->nodes[i].id == 1) { mark[i] = 1; marked = 1; }
        int changed = 1;
        while (changed) {
            changed = 0;
            for (size_t i = 0; i < ix->count; i++) {
                if (mark[i]) continue;
                const fv_node *n = &ix->nodes[i];
                if (n->parent == 0) continue;
                for (size_t k = 0; k < ix->count; k++) {
                    if (!mark[k]) continue;
                    const fv_node *pk = &ix->nodes[k];
                    if (pk->id != n->parent) continue;
                    if (pk->type != FV_NODE_DIR) { free(mark); goto bad; }
                    mark[i] = 1;
                    marked++;
                    changed = 1;
                    break;
                }
            }
        }
        free(mark);
        if (marked != ix->count) goto bad;               /* цикл или сирота */
    }

    ix->next_id = (nid > max_id) ? nid : max_id + 1;
    return FV_OK;

bad:
    fv_index_free(ix);
    return FV_ERR_FORMAT;
}

void fv_index_totals(const fv_index *ix, size_t *files, size_t *dirs, uint64_t *bytes)
{
    size_t f = 0, d = 0;
    uint64_t b = 0;
    if (ix) {
        for (size_t i = 0; i < ix->count; i++) {
            if (ix->nodes[i].type == FV_NODE_FILE) {
                f++;
                b += ix->nodes[i].size;
            } else if (ix->nodes[i].id != 1) {
                d++;
            }
        }
    }
    if (files) *files = f;
    if (dirs)  *dirs = d;
    if (bytes) *bytes = b;
}
