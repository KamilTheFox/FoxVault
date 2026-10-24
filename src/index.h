/* index.h — дерево каталогов и имён внутри контейнера.
 *
 * Индекс хранится целиком в зашифрованном виде: узлы сериализуются,
 * шифруются (AES-256-GCM ключом контейнера) и записываются в два слота
 * с номером поколения (vault.c). Здесь — только структура данных и
 * операции над ней, без криптографии и диска.
 */
#ifndef FV_INDEX_H
#define FV_INDEX_H

#include "util.h"

#define FV_NODE_DIR  1u
#define FV_NODE_FILE 2u

#define FV_NAME_MAX 255          /* байт UTF-8, без завершающего нуля */

typedef struct {
    uint64_t id;                 /* уникальный номер; корень всегда 1 */
    uint64_t parent;             /* 0 только у корня */
    uint8_t  type;               /* FV_NODE_DIR / FV_NODE_FILE */
    char     name[FV_NAME_MAX + 1];  /* имя внутри одного каталога */
    /* только для файлов: */
    char     blob[33];           /* имя блоба: 32 hex-символа без расширения */
    uint64_t size;               /* размер открытого текста, байт */
    uint32_t chunk_size;         /* размер чанка шифрования */
    uint64_t mtime;              /* unix-время, секунды */
} fv_node;

typedef struct {
    fv_node *nodes;
    size_t   count, cap;
    uint64_t next_id;            /* следующий свободный id */
} fv_index;

/* Результат поиска пути: заполнен и когда объект найден (id != 0),
 * и когда не найден, но существует родитель последнего компонента. */
typedef struct {
    uint64_t id;
    uint64_t parent;             /* 0 — родителя нет / путь ведёт в никуда */
    char     name[FV_NAME_MAX + 1];
} fv_loc;

void fv_index_init(fv_index *ix);
void fv_index_free(fv_index *ix);
int  fv_index_make_root(fv_index *ix);

/* Канонизация пути: "//a/./b/.." -> "/a"; ".." выше корня — ошибка.
 * Заодно проверяет имена компонентов. */
int  fv_index_norm_path(const char *in, char *out, size_t outlen);

int  fv_index_resolve_ex(const fv_index *ix, const char *path, fv_loc *loc);
int  fv_index_resolve(const fv_index *ix, const char *path, uint64_t *id);

fv_node       *fv_index_node(fv_index *ix, uint64_t id);
const fv_node *fv_index_get(const fv_index *ix, uint64_t id);
int            fv_index_has_children(const fv_index *ix, uint64_t id);

/* Добавить узел; возвращает id или 0 (нет родителя/имя плохое/нет памяти).
 * Имя не должно конфликтовать — вызывающий сначала проверил. */
uint64_t fv_index_add_node(fv_index *ix, uint64_t parent, const char *name,
                           uint8_t type, uint64_t mtime);
void     fv_index_remove_one(fv_index *ix, uint64_t id);

/* Поддерево целиком (включая корень поддерева) — копии узлов.
 * out выделяется malloc'ом, освобождает вызывающий. */
int  fv_index_collect_subtree(const fv_index *ix, uint64_t id,
                              fv_node **out, size_t *count);
void fv_index_remove_ids(fv_index *ix, const uint64_t *ids, size_t n);
void fv_index_restore_nodes(fv_index *ix, const fv_node *nodes, size_t n);

/* Дети каталога в отсортированном порядке: сначала каталоги, потом по имени */
typedef int (*fv_list_cb)(const fv_node *n, void *ctx);
int  fv_index_list(const fv_index *ix, uint64_t dir_id, fv_list_cb cb, void *ctx);

/* Сериализация в плоский байтовый буфер (ещё не шифрованный) */
int  fv_index_serialize(const fv_index *ix, fv_buf *out);
/* Обратная операция с полной проверкой структуры (на входе — расшифрованное) */
int  fv_index_deserialize(fv_index *ix, const uint8_t *p, size_t len);

void fv_index_totals(const fv_index *ix, size_t *files, size_t *dirs, uint64_t *bytes);

#endif
