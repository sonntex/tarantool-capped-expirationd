#include <tarantool/module.h>
#include <msgpuck.h>

static const char nil_key[] = { 0x90 };

static const uint32_t def_scan_tuples_per_it = 1024;
static const uint32_t def_scan_time = 3600;

struct expirationd_task
{
  struct expirationd_task *next;
  struct expirationd_task *prev;
  struct fiber *fiber;
  char name[256];
  uint32_t space_id;
  uint32_t rm_index_id;
  uint32_t it_index_id;
  uint32_t it_index_iter;
  uint32_t field_no;
  uint32_t scan_tuples_per_it;
  uint32_t scan_tuples;
  uint32_t scan_time;
};

static struct expirationd_task *task_list = NULL;

static struct expirationd_task *
expirationd_alloc()
{
  struct expirationd_task *task = (struct expirationd_task *)calloc(1, sizeof(struct expirationd_task));
  task->scan_tuples_per_it = def_scan_tuples_per_it;
  task->scan_time = def_scan_time;
  return task;
}

static struct expirationd_task *
expirationd_find(const char *name)
{
  if (task_list) {
    for (struct expirationd_task *task = task_list; task; task = task->next) {
      if (strcmp(task->name, name) == 0)
        return task;
    }
  }
  return NULL;
}

static bool
expirationd_expired(struct expirationd_task *task, box_tuple_t *tuple)
{
  const char *buf = box_tuple_field(tuple, task->field_no - 1);
  if (!buf || mp_typeof(*buf) != MP_UINT)
    return false;
  uint64_t now = fiber_time64() / 1000000;
  uint64_t val = mp_decode_uint(&buf);
  if (val > now)
    return false;
  return true;
}

static void
expirationd_delete(struct expirationd_task *task, box_tuple_t *tuple)
{
  uint32_t len;
  const char *str = box_tuple_extract_key(tuple, task->space_id, task->rm_index_id, &len);
  box_delete(task->space_id, task->rm_index_id, str, str + len, NULL);
}

static double
expirationd_delay(struct expirationd_task *task, uint64_t space_len)
{
  double delay = (double)(task->scan_tuples_per_it * task->scan_time) / space_len;
  if (delay > 1.)
    delay = 1.;
  else if (delay < 0.001)
    delay = 0.001;
  return delay;
}

static void
expirationd_suspend(struct expirationd_task *task)
{
  if (++task->scan_tuples >= task->scan_tuples_per_it) {
    task->scan_tuples = 0;
    uint64_t space_len = box_index_len(task->space_id, task->it_index_id);
    if (space_len)
      fiber_sleep(expirationd_delay(task, space_len));
  }
}

static void
expirationd_iterate(struct expirationd_task *task)
{
  box_tuple_t *tuple;
  box_iterator_t *iter = box_index_iterator(task->space_id, task->it_index_id, task->it_index_iter, nil_key, 0);
  task->scan_tuples = 0;
  while (box_iterator_next(iter, &tuple) == 0 && tuple) {
    if (expirationd_expired(task, tuple))
      expirationd_delete(task, tuple);
    else if (task->it_index_id != task->rm_index_id && task->it_index_iter == ITER_GT)
      break;
    expirationd_suspend(task);
  }
  box_iterator_free(iter);
}

static int
expirationd_work(va_list args)
{
  struct expirationd_task *task = va_arg(args, struct expirationd_task *);
  fiber_set_cancellable(1);
  while (!fiber_is_cancelled()) {
    expirationd_iterate(task);
    fiber_sleep(1.f);
  }
  return 0;
}

static bool
expirationd_parse_name(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_STR)
    return false;
  uint32_t len;
  const char *str = mp_decode_str(pos, &len);
  if (len >= 256)
    return false;
  memcpy(task->name, str, len);
  task->name[len] = 0;
  return true;
}

static bool
expirationd_parse_space_id(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->space_id = mp_decode_uint(pos);
  return true;
}

static bool
expirationd_parse_rm_index_id(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->rm_index_id = mp_decode_uint(pos);
  return true;
}

static bool
expirationd_parse_rm_index_unique(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_BOOL)
    return false;
  bool unique = mp_decode_bool(pos);
  if (!unique)
    return false;
  return true;
}

static bool
expirationd_parse_rm_index(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_MAP)
    return false;
  uint32_t size = mp_decode_map(pos);
  for (uint32_t i = 0; i < size; ++i) {
    if (mp_typeof(**pos) == MP_STR) {
      uint32_t len;
      const char *str = mp_decode_str(pos, &len);
      if (strncmp(str, "id", len) == 0) {
        if (!expirationd_parse_rm_index_id(task, pos))
          return false;
      } else if (strncmp(str, "unique", len) == 0) {
        if (!expirationd_parse_rm_index_unique(task, pos))
          return false;
      } else
        mp_next(pos);
    } else
      mp_next(pos);
  }
  return true;
}

static bool
expirationd_parse_it_index_id(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->it_index_id = mp_decode_uint(pos);
  return true;
}

static bool
expirationd_parse_it_index_iter(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_STR)
    return false;
  uint32_t len;
  const char *str = mp_decode_str(pos, &len);
  if (strncmp(str, "TREE", len) == 0)
    task->it_index_iter = ITER_GT;
  else
    task->it_index_iter = ITER_ALL;
  return true;
}

static bool
expirationd_parse_it_index(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_MAP)
    return false;
  uint32_t size = mp_decode_map(pos);
  for (uint32_t i = 0; i < size; ++i) {
    if (mp_typeof(**pos) == MP_STR) {
      uint32_t len;
      const char *str = mp_decode_str(pos, &len);
      if (strncmp(str, "id", len) == 0) {
        if (!expirationd_parse_it_index_id(task, pos))
          return false;
      } else if (strncmp(str, "type", len) == 0) {
        if (!expirationd_parse_it_index_iter(task, pos))
          return false;
      } else
        mp_next(pos);
    } else
      mp_next(pos);
  }
  return true;
}

static bool
expirationd_parse_field_no(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->field_no = mp_decode_uint(pos);
  if (task->field_no == 0)
    return false;
  return true;
}

static bool
expirationd_parse_scan_tuples_per_it(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->scan_tuples_per_it = mp_decode_uint(pos);
  return true;
}

static bool
expirationd_parse_scan_time(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->scan_time = mp_decode_uint(pos);
  return true;
}

API_EXPORT int
start(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
  struct expirationd_task *found;
  struct expirationd_task *task = expirationd_alloc();
  if (mp_typeof(*args) != MP_ARRAY || mp_decode_array(&args) != 7) {
    say_error("capped-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  if (!expirationd_parse_name(task, &args) ||
      !expirationd_parse_space_id(task, &args) ||
      !expirationd_parse_rm_index(task, &args) ||
      !expirationd_parse_it_index(task, &args) ||
      !expirationd_parse_field_no(task, &args) ||
      !expirationd_parse_scan_tuples_per_it(task, &args) ||
      !expirationd_parse_scan_time(task, &args)) {
    free(task);
    say_error("capped-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  found = expirationd_find(task->name);
  if (found) {
    free(task);
    say_error("capped-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  task->fiber = fiber_new(task->name, &expirationd_work);
  fiber_set_joinable(task->fiber, 1);
  task->next = task_list;
  task_list = task;
  fiber_start(task->fiber, task);
  return 0;
}

API_EXPORT int
kill(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
  struct expirationd_task *found;
  struct expirationd_task *task = expirationd_alloc();
  if (mp_typeof(*args) != MP_ARRAY || mp_decode_array(&args) != 1) {
    say_error("capped-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  if (!expirationd_parse_name(task, &args)) {
    free(task);
    say_error("capped-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  found = expirationd_find(task->name);
  if (found) {
    if (found->prev)
      found->prev->next = found->next;
    if (found->next)
      found->next->prev = found->prev;
    fiber_cancel(found->fiber);
    fiber_join(found->fiber);
    free(found);
  }
  free(task);
  return 0;
}
