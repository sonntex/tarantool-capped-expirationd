#include <tarantool/module.h>
#include <msgpuck.h>

static const char nil_key[] = { 0x90 };

static const uint32_t def_scan_size = 1024;
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
  uint32_t it_index_type;
  uint32_t field_no;
  uint32_t scan_size;
  uint32_t scan_time;
};

static struct expirationd_task *task_list = NULL;

static struct expirationd_task *
expirationd_alloc()
{
  struct expirationd_task *task =
      (struct expirationd_task *)calloc(1, sizeof(struct expirationd_task));
  task->scan_size = def_scan_size;
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
expirationd_breakable(struct expirationd_task *task)
{
  return task->it_index_id != task->rm_index_id && task->it_index_type == ITER_GT;
}

static bool
expirationd_expired(struct expirationd_task *task, box_tuple_t *tuple)
{
  const char *buf = box_tuple_field(tuple, task->field_no - 1);
  if (!buf || mp_typeof(*buf) != MP_UINT)
    return false;
  uint64_t val = mp_decode_uint(&buf);
  if (val > fiber_time64() / 1000000)
    return false;
  return true;
}

static void
expirationd_delete(struct expirationd_task *task, box_tuple_t *tuple)
{
  uint32_t len;
  const char *str = box_tuple_extract_key(
      tuple,
      task->space_id,
      task->rm_index_id,
      &len);
  box_delete(task->space_id, task->rm_index_id, str, str + len, NULL);
}

static bool
expirationd_iterate(struct expirationd_task *task, box_iterator_t **iterp)
{
  box_iterator_t *iter = *iterp;
  box_txn_begin();
  for (uint32_t i = 0; i < task->scan_size; ++i) {
    box_tuple_t *tuple = NULL;
    if (box_iterator_next(iter, &tuple) < 0) {
      box_iterator_free(iter);
      *iterp = NULL;
      box_txn_rollback();
      return false;
    }
    if (!tuple) {
      box_iterator_free(iter);
      *iterp = NULL;
      box_txn_commit();
      return true;
    }
    if (expirationd_expired(task, tuple))
      expirationd_delete(task, tuple);
    else if (expirationd_breakable(task))
      break;
  }
  box_txn_commit();
  return true;
}

static bool
expirationd_suspend(struct expirationd_task *task)
{
  double delay = ((double)task->scan_size * task->scan_time) /
      (box_index_len(task->space_id, task->it_index_id) + 1);
  if (delay > 1)
    delay = 1;
  fiber_set_cancellable(true);
  fiber_sleep(delay);
  if (fiber_is_cancelled())
    return false;
  fiber_set_cancellable(false);
  return true;
}

static void
expirationd_loop(struct expirationd_task *task)
{
  box_iterator_t *iter = NULL;
  while (true) {
    if (!iter)
      iter = box_index_iterator(
          task->space_id,
          task->it_index_id,
          task->it_index_type,
          nil_key, 0);
    if (!iter) {
      say_error("capped-expirationd: index error");
      break;
    }
    if (!expirationd_iterate(task, &iter))
      break;
    if (!expirationd_suspend(task))
      break;
  }
  if (iter)
    box_iterator_free(iter);
}

static int
expirationd_work(va_list args)
{
  struct expirationd_task *task = va_arg(args, struct expirationd_task *);
  expirationd_loop(task);
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
expirationd_parse_it_index_type(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_STR)
    return false;
  uint32_t len;
  const char *str = mp_decode_str(pos, &len);
  if (strncmp(str, "TREE", len) == 0)
    task->it_index_type = ITER_GT;
  else
    task->it_index_type = ITER_ALL;
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
        if (!expirationd_parse_it_index_type(task, pos))
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
expirationd_parse_scan_size(struct expirationd_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT)
    return false;
  task->scan_size = mp_decode_uint(pos);
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
      !expirationd_parse_scan_size(task, &args) ||
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
  task->next = task_list;
  task_list = task;
  fiber_set_joinable(task->fiber, true);
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
