/* rx.c — регулярные выражения: разбор в дерево, компиляция в программу,
 * поиск виртуальной машиной Пайка (Thompson NFA с приоритетами потоков).
 *
 * Схема по Russ Cox, «Regular Expression Matching: the Virtual Machine
 * Approach». Каждый поток — (pc, начало совпадения); на каждой позиции
 * потоки двигаются вместе, дубликаты по pc отбрасываются, поэтому время
 * O(длина строки × размер программы). */
#include "rx.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RX_MAX_PATTERN 1024                 /* байт шаблона */
#define RX_MAX_NODES   8192
#define RX_MAX_INSTS   16384

/* ---------- классы символов ---------- */

typedef struct {
    uint32_t lo, hi;
} rng;

typedef struct {
    rng   *r;
    size_t n, cap;
    int    neg;
} rclass;

static int class_add(rclass *c, uint32_t lo, uint32_t hi)
{
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 8;
        rng *nr = (rng *)realloc(c->r, nc * sizeof(rng));
        if (!nr) return 0;
        c->r = nr;
        c->cap = nc;
    }
    c->r[c->n].lo = lo;
    c->r[c->n].hi = hi;
    c->n++;
    return 1;
}

static int class_has(const rclass *c, uint32_t ch, int icase)
{
    uint32_t f = icase ? fv_fold_cp(ch) : ch;
    int in = 0;
    for (size_t i = 0; i < c->n && !in; i++) {
        if (ch >= c->r[i].lo && ch <= c->r[i].hi) in = 1;
        else if (icase && f >= fv_fold_cp(c->r[i].lo) && f <= fv_fold_cp(c->r[i].hi)) in = 1;
    }
    return in != c->neg;
}

/* \d \w \s — общие наборы (\w понимает и кириллицу) */
static int class_add_named(rclass *c, char k)
{
    switch (k) {
    case 'd': return class_add(c, '0', '9');
    case 'w': return class_add(c, '0', '9') && class_add(c, 'A', 'Z') &&
                     class_add(c, 'a', 'z') && class_add(c, '_', '_') &&
                     class_add(c, 0x400, 0x4FF);
    case 's': return class_add(c, ' ', ' ') && class_add(c, '\t', '\r');
    default:  return 0;
    }
}

/* ---------- дерево разбора ---------- */

enum { N_CHAR, N_ANY, N_CLASS, N_BOL, N_EOL, N_EMPTY,
       N_CAT, N_ALT, N_STAR, N_PLUS, N_QUEST };

typedef struct {
    int      t;
    uint32_t c;                     /* символ или номер класса */
    int      a, b;                  /* дети */
} node;

typedef struct {
    const char *p, *end;
    node       *nd;
    size_t      nn;
    rclass     *cls;
    size_t      ncls, capcls;
    int         icase;
    const char *err;
} parser;

static int mk(parser *ps, int t, uint32_t c, int a, int b)
{
    if (ps->nn >= RX_MAX_NODES) { ps->err = "шаблон слишком сложный"; return -1; }
    node *n = &ps->nd[ps->nn];
    n->t = t;
    n->c = c;
    n->a = a;
    n->b = b;
    return (int)ps->nn++;
}

static int new_class(parser *ps)
{
    if (ps->ncls == ps->capcls) {
        size_t nc = ps->capcls ? ps->capcls * 2 : 8;
        rclass *n = (rclass *)realloc(ps->cls, nc * sizeof(rclass));
        if (!n) { ps->err = "нет памяти"; return -1; }
        ps->cls = n;
        ps->capcls = nc;
    }
    memset(&ps->cls[ps->ncls], 0, sizeof(rclass));
    return (int)ps->ncls++;
}

static int parse_alt(parser *ps);

/* [ ... ] — после '[' */
static int parse_class(parser *ps)
{
    int ci = new_class(ps);
    if (ci < 0) return -1;
    rclass *c = &ps->cls[ci];
    if (ps->p < ps->end && *ps->p == '^') { c->neg = 1; ps->p++; }
    int first = 1;
    for (;;) {
        if (ps->p >= ps->end) { ps->err = "не закрыта скобка ["; return -1; }
        if (*ps->p == ']' && !first) { ps->p++; break; }
        first = 0;
        uint32_t lo;
        if (*ps->p == '\\' && ps->p + 1 < ps->end) {
            char k = ps->p[1];
            if (k == 'd' || k == 'w' || k == 's') {
                ps->p += 2;
                c = &ps->cls[ci];
                if (!class_add_named(c, k)) { ps->err = "нет памяти"; return -1; }
                continue;
            }
            ps->p++;
            lo = fv_u8_decode(&ps->p, ps->end);
            if (lo == 't') lo = '\t';
        } else {
            lo = fv_u8_decode(&ps->p, ps->end);
        }
        uint32_t hi = lo;
        if (ps->p + 1 < ps->end && *ps->p == '-' && ps->p[1] != ']') {
            ps->p++;
            if (*ps->p == '\\' && ps->p + 1 < ps->end) ps->p++;
            hi = fv_u8_decode(&ps->p, ps->end);
            if (hi < lo) { ps->err = "неверный диапазон в [...]"; return -1; }
        }
        c = &ps->cls[ci];
        if (!class_add(c, lo, hi)) { ps->err = "нет памяти"; return -1; }
    }
    return mk(ps, N_CLASS, (uint32_t)ci, -1, -1);
}

static int parse_atom(parser *ps)
{
    char ch = *ps->p;
    if (ch == '(') {
        ps->p++;
        int e = parse_alt(ps);
        if (e < 0) return -1;
        if (ps->p >= ps->end || *ps->p != ')') { ps->err = "не закрыта скобка ("; return -1; }
        ps->p++;
        return e;
    }
    if (ch == '.') { ps->p++; return mk(ps, N_ANY, 0, -1, -1); }
    if (ch == '^') { ps->p++; return mk(ps, N_BOL, 0, -1, -1); }
    if (ch == '$') { ps->p++; return mk(ps, N_EOL, 0, -1, -1); }
    if (ch == '[') { ps->p++; return parse_class(ps); }
    if (ch == '*' || ch == '+' || ch == '?') {
        ps->err = "*, + или ? не к чему применить";
        return -1;
    }
    if (ch == '\\') {
        ps->p++;
        if (ps->p >= ps->end) { ps->err = "\\ в конце шаблона"; return -1; }
        char k = *ps->p;
        char lk = (char)(k | 0x20);
        if ((lk == 'd' || lk == 'w' || lk == 's') && (k == lk || k == (char)(lk & ~0x20))) {
            ps->p++;
            int ci = new_class(ps);
            if (ci < 0) return -1;
            if (!class_add_named(&ps->cls[ci], lk)) { ps->err = "нет памяти"; return -1; }
            ps->cls[ci].neg = (k != lk);              /* \D \W \S */
            return mk(ps, N_CLASS, (uint32_t)ci, -1, -1);
        }
        uint32_t c = fv_u8_decode(&ps->p, ps->end);
        if (c == 't') c = '\t';
        return mk(ps, N_CHAR, ps->icase ? fv_fold_cp(c) : c, -1, -1);
    }
    uint32_t c = fv_u8_decode(&ps->p, ps->end);
    return mk(ps, N_CHAR, ps->icase ? fv_fold_cp(c) : c, -1, -1);
}

static int parse_repeat(parser *ps)
{
    int e = parse_atom(ps);
    if (e < 0) return -1;
    while (ps->p < ps->end && (*ps->p == '*' || *ps->p == '+' || *ps->p == '?')) {
        int t = (*ps->p == '*') ? N_STAR : (*ps->p == '+') ? N_PLUS : N_QUEST;
        ps->p++;
        e = mk(ps, t, 0, e, -1);
        if (e < 0) return -1;
    }
    return e;
}

static int parse_cat(parser *ps)
{
    int e = -1;
    while (ps->p < ps->end && *ps->p != '|' && *ps->p != ')') {
        int r = parse_repeat(ps);
        if (r < 0) return -1;
        e = (e < 0) ? r : mk(ps, N_CAT, 0, e, r);
        if (e < 0) return -1;
    }
    return e < 0 ? mk(ps, N_EMPTY, 0, -1, -1) : e;
}

static int parse_alt(parser *ps)
{
    int e = parse_cat(ps);
    if (e < 0) return -1;
    while (ps->p < ps->end && *ps->p == '|') {
        ps->p++;
        int r = parse_cat(ps);
        if (r < 0) return -1;
        e = mk(ps, N_ALT, 0, e, r);
        if (e < 0) return -1;
    }
    return e;
}

/* ---------- программа ---------- */

enum { I_CHAR, I_ANY, I_CLASS, I_BOL, I_EOL, I_SPLIT, I_JMP, I_MATCH };

typedef struct {
    int      op;
    uint32_t c;
    int      x, y;
} inst;

struct fv_rx {
    inst   *code;
    size_t  n;
    rclass *cls;
    size_t  ncls;
    int     icase;
};

static size_t node_size(const node *nd, int i)
{
    const node *n = &nd[i];
    switch (n->t) {
    case N_CAT:   return node_size(nd, n->a) + node_size(nd, n->b);
    case N_ALT:   return 2 + node_size(nd, n->a) + node_size(nd, n->b);
    case N_STAR:  return 2 + node_size(nd, n->a);
    case N_PLUS:  return 1 + node_size(nd, n->a);
    case N_QUEST: return 1 + node_size(nd, n->a);
    case N_EMPTY: return 0;
    default:      return 1;
    }
}

static void emit(fv_rx *rx, const node *nd, int i)
{
    const node *n = &nd[i];
    inst *I;
    size_t L1, L2;
    switch (n->t) {
    case N_CHAR:  I = &rx->code[rx->n++]; I->op = I_CHAR;  I->c = n->c; break;
    case N_ANY:   I = &rx->code[rx->n++]; I->op = I_ANY;   break;
    case N_CLASS: I = &rx->code[rx->n++]; I->op = I_CLASS; I->c = n->c; break;
    case N_BOL:   I = &rx->code[rx->n++]; I->op = I_BOL;   break;
    case N_EOL:   I = &rx->code[rx->n++]; I->op = I_EOL;   break;
    case N_EMPTY: break;
    case N_CAT:   emit(rx, nd, n->a); emit(rx, nd, n->b); break;
    case N_ALT:                                  /* split L1,L2; L1: a; jmp L3; L2: b; L3: */
        L1 = rx->n++;
        rx->code[L1].op = I_SPLIT;
        rx->code[L1].x = (int)rx->n;
        emit(rx, nd, n->a);
        L2 = rx->n++;
        rx->code[L2].op = I_JMP;
        rx->code[L1].y = (int)rx->n;
        emit(rx, nd, n->b);
        rx->code[L2].x = (int)rx->n;
        break;
    case N_STAR:                                 /* L1: split L2,L3; L2: a; jmp L1; L3: */
        L1 = rx->n++;
        rx->code[L1].op = I_SPLIT;
        rx->code[L1].x = (int)rx->n;
        emit(rx, nd, n->a);
        I = &rx->code[rx->n++];
        I->op = I_JMP;
        I->x = (int)L1;
        rx->code[L1].y = (int)rx->n;
        break;
    case N_PLUS:                                 /* L1: a; split L1,L2; L2: */
        L1 = rx->n;
        emit(rx, nd, n->a);
        I = &rx->code[rx->n++];
        I->op = I_SPLIT;
        I->x = (int)L1;
        I->y = (int)rx->n;
        break;
    case N_QUEST:                                /* split L1,L2; L1: a; L2: */
        L1 = rx->n++;
        rx->code[L1].op = I_SPLIT;
        rx->code[L1].x = (int)rx->n;
        emit(rx, nd, n->a);
        rx->code[L1].y = (int)rx->n;
        break;
    default: break;
    }
}

static void free_classes(rclass *c, size_t n)
{
    for (size_t i = 0; i < n; i++) free(c[i].r);
    free(c);
}

int fv_rx_compile(fv_rx **out, const char *pat, int icase, int fixed, const char **err)
{
    *out = NULL;
    *err = NULL;
    size_t plen = strlen(pat);
    if (plen > RX_MAX_PATTERN) { *err = "шаблон слишком длинный"; return FV_ERR_RANGE; }

    parser ps;
    memset(&ps, 0, sizeof ps);
    ps.p = pat;
    ps.end = pat + plen;
    ps.icase = icase;
    ps.nd = (node *)malloc(RX_MAX_NODES * sizeof(node));
    if (!ps.nd) { *err = "нет памяти"; return FV_ERR_NOMEM; }

    int root;
    if (fixed) {                                 /* -F: просто цепочка символов */
        root = -1;
        while (ps.p < ps.end) {
            uint32_t c = fv_u8_decode(&ps.p, ps.end);
            int r = mk(&ps, N_CHAR, icase ? fv_fold_cp(c) : c, -1, -1);
            if (r < 0) break;
            root = (root < 0) ? r : mk(&ps, N_CAT, 0, root, r);
            if (root < 0) break;
        }
        if (!ps.err && root < 0) root = mk(&ps, N_EMPTY, 0, -1, -1);
    } else {
        root = parse_alt(&ps);
        if (root >= 0 && ps.p < ps.end) {        /* лишняя ')' */
            ps.err = "лишняя закрывающая скобка )";
            root = -1;
        }
    }
    if (root < 0 || ps.err) {
        *err = ps.err ? ps.err : "ошибка в шаблоне";
        free(ps.nd);
        free_classes(ps.cls, ps.ncls);
        return FV_ERR_ARG;
    }

    size_t need = node_size(ps.nd, root) + 1;
    if (need > RX_MAX_INSTS) {
        *err = "шаблон слишком сложный";
        free(ps.nd);
        free_classes(ps.cls, ps.ncls);
        return FV_ERR_RANGE;
    }
    fv_rx *rx = (fv_rx *)calloc(1, sizeof *rx);
    if (rx) rx->code = (inst *)calloc(need, sizeof(inst));
    if (!rx || !rx->code) {
        free(rx);
        free(ps.nd);
        free_classes(ps.cls, ps.ncls);
        *err = "нет памяти";
        return FV_ERR_NOMEM;
    }
    emit(rx, ps.nd, root);
    rx->code[rx->n++].op = I_MATCH;
    rx->cls = ps.cls;
    rx->ncls = ps.ncls;
    rx->icase = icase;
    free(ps.nd);
    *out = rx;
    return FV_OK;
}

void fv_rx_free(fv_rx *rx)
{
    if (!rx) return;
    free(rx->code);
    free_classes(rx->cls, rx->ncls);
    free(rx);
}

/* ---------- виртуальная машина Пайка ---------- */

typedef struct {
    int    pc;
    size_t start;
} thr;

typedef struct {
    thr      *t;
    size_t    n;
    unsigned *mark;                 /* mark[pc] == gen — pc уже в списке */
    unsigned  gen;
} tlist;

/* добавить поток со всеми переходами по JMP/SPLIT и проверкой ^ $;
 * порядок обхода сохраняет приоритет (сначала x, потом y) */
static void add(tlist *l, const fv_rx *rx, int pc0, size_t start,
                size_t at, size_t len, int *stack)
{
    int sp = 0;
    stack[sp++] = pc0;
    while (sp) {
        int pc = stack[--sp];
        if (l->mark[pc] == l->gen) continue;
        l->mark[pc] = l->gen;
        const inst *I = &rx->code[pc];
        switch (I->op) {
        case I_JMP:   stack[sp++] = I->x; break;
        case I_SPLIT: stack[sp++] = I->y; stack[sp++] = I->x; break;
        case I_BOL:   if (at == 0)   stack[sp++] = pc + 1; break;
        case I_EOL:   if (at == len) stack[sp++] = pc + 1; break;
        default:
            l->t[l->n].pc = pc;
            l->t[l->n].start = start;
            l->n++;
        }
    }
}

int fv_rx_search(const fv_rx *rx, const char *s, size_t len, size_t from,
                 size_t *ms, size_t *me)
{
    if (!rx || from > len) return 0;
    size_t n = rx->n;
    thr *ta = (thr *)malloc(2 * n * sizeof(thr));
    unsigned *mk_ = (unsigned *)calloc(2 * n, sizeof(unsigned));
    int *stack = (int *)malloc(2 * n * sizeof(int) + sizeof(int));
    if (!ta || !mk_ || !stack) {
        free(ta);
        free(mk_);
        free(stack);
        return 0;
    }
    tlist A = { ta, 0, mk_, 1 }, B = { ta + n, 0, mk_ + n, 1 };
    tlist *cl = &A, *nl = &B;

    int matched = 0;
    size_t pos = from;
    add(cl, rx, 0, pos, pos, len, stack);
    for (;;) {
        int have = pos < len;
        uint32_t c = 0;
        size_t nxt = pos;
        if (have) {
            const char *p = s + pos;
            c = fv_u8_decode(&p, s + len);
            nxt = (size_t)(p - s);
        }
        uint32_t fc = rx->icase ? fv_fold_cp(c) : c;
        nl->n = 0;
        nl->gen++;
        for (size_t i = 0; i < cl->n; i++) {
            const inst *I = &rx->code[cl->t[i].pc];
            int ok = 0;
            switch (I->op) {
            case I_MATCH:
                matched = 1;
                *ms = cl->t[i].start;
                *me = pos;
                i = cl->n;                       /* потоки ниже по приоритету — отбросить */
                continue;
            case I_CHAR:  ok = have && fc == I->c; break;
            case I_ANY:   ok = have; break;
            case I_CLASS: ok = have && class_has(&rx->cls[I->c], c, rx->icase); break;
            default: break;
            }
            if (ok) add(nl, rx, cl->t[i].pc + 1, cl->t[i].start, nxt, len, stack);
        }
        if (!have) break;
        pos = nxt;
        if (!matched) add(nl, rx, 0, pos, pos, len, stack);  /* новое начало — ниже приоритетом */
        tlist *tmp = cl;
        cl = nl;
        nl = tmp;
        if (cl->n == 0) break;
    }
    /* потоки, дошедшие до конца строки, проверяются в последней итерации
     * (have == 0): там I_MATCH ловится до выхода из цикла */
    free(ta);
    free(mk_);
    free(stack);
    return matched;
}
