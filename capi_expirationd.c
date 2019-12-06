#include <tarantool/module.h>
#include <msgpuck.h>

static const char nil_key[] = { 0x90 };

static const uint32_t def_scan_tuples_per_it = 1024;
static const uint32_t def_scan_time = 3600;

struct fiber_task
{
  struct fiber_task *next;
  struct fiber_task *prev;
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

static struct fiber_task *task_list = NULL;

static struct fiber_task *
task_alloc()
{
  struct fiber_task *task = (struct fiber_task *)calloc(1, sizeof(struct fiber_task));
  task->scan_tuples_per_it = def_scan_tuples_per_it;
  task->scan_time = def_scan_time;
  return task;
}

static struct fiber_task *
task_find(const char *name)
{
  if (task_list) {
    for (struct fiber_task *task = task_list; task; task = task->next) {
      if (strcmp(task->name, name) == 0)
        return task;
    }
  }
  return NULL;
}

static int
expired(struct fiber_task *task, box_tuple_t *tuple)
{
  const char *buf = box_tuple_field(tuple, task->field_no - 1);
  if (!buf || mp_typeof(*buf) != MP_UINT)
    return 0;
  uint64_t now = fiber_time64() / 1000000;
  uint64_t val = mp_decode_uint(&buf);
  if (val > now)
    return 0;
  return 1;
}

static void
delete(struct fiber_task *task, box_tuple_t *tuple)
{
  uint32_t len;
  const char *key = box_tuple_extract_key(tuple, task->space_id, task->rm_index_id, &len);
  box_delete(task->space_id, task->rm_index_id, key, key + len, NULL);
}

static double
delay(struct fiber_task *task, uint64_t space_len)
{
  double delay = (double)(task->scan_tuples_per_it * task->scan_time) / space_len;
  if (delay > 1.)
    delay = 1.;
  else if (delay < 0.001)
    delay = 0.001;
  return delay;
}

static void
suspend(struct fiber_task *task)
{
  if (++task->scan_tuples >= task->scan_tuples_per_it) {
    task->scan_tuples = 0;
    uint64_t space_len = box_index_len(task->space_id, task->it_index_id);
    if (space_len)
      fiber_sleep(delay(task, space_len));
  }
}

static void
iterate(struct fiber_task *task)
{
  box_tuple_t *tuple;
  box_iterator_t *iter = box_index_iterator(task->space_id, task->it_index_id, task->it_index_iter, nil_key, 0);
  task->scan_tuples = 0;
  while (box_iterator_next(iter, &tuple) == 0 && tuple) {
    if (expired(task, tuple))
      delete(task, tuple);
    else if (task->it_index_id != task->rm_index_id && task->it_index_iter == ITER_GT)
      break;
    suspend(task);
  }
  box_iterator_free(iter);
}

static int
work(va_list args)
{
  struct fiber_task *task = va_arg(args, struct fiber_task *);
  fiber_set_cancellable(1);
  while (!fiber_is_cancelled()) {
    iterate(task);
    fiber_sleep(1.f);
  }
  return 0;
}

static int
parse_name(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_STR) {
    say_error("capi-expirationd: illegal params (task.name)");
    return 0;
  }
  uint32_t len;
  const char *str = mp_decode_str(pos, &len);
  if (len >= 256) {
    say_error("capi-expirationd: illegal params (task.name)");
    return 0;
  }
  memcpy(task->name, str, len);
  task->name[len] = 0;
  return 1;
}

static int
parse_space_id(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT) {
    say_error("capi-expirationd: illegal params (task.space_id)");
    return 0;
  }
  task->space_id = mp_decode_uint(pos);
  return 1;
}

static int
parse_rm_index_id(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT) {
    say_error("capi-expirationd: illegal params (task.rm_index_id)");
    return 0;
  }
  task->rm_index_id = mp_decode_uint(pos);
  return 1;
}

static int
parse_rm_index_unique(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_BOOL || !mp_decode_bool(pos)) {
    say_error("capi-expirationd: illegal params (task.rm_index_id)");
    return 0;
  }
  return 1;
}

static int
parse_rm_index(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_MAP) {
    say_error("capi-expirationd: illegal params (task.rm_index)");
    return 0;
  }
  uint32_t size = mp_decode_map(pos);
  for (uint32_t i = 0; i < size; ++i) {
    if (mp_typeof(**pos) == MP_STR) {
      uint32_t len;
      const char *str = mp_decode_str(pos, &len);
      if (strncmp(str, "id", len) == 0) {
        if (!parse_rm_index_id(task, pos))
          return 0;
      } else if (strncmp(str, "unique", len) == 0) {
        if (!parse_rm_index_unique(task, pos))
          return 0;
      } else
        mp_next(pos);
    } else
      mp_next(pos);
  }
  return 1;
}

static int
parse_it_index_id(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT) {
    say_error("capi-expirationd: illegal params (task.it_index_id)");
    return 0;
  }
  task->it_index_id = mp_decode_uint(pos);
  return 1;
}

static int
parse_it_index_iter(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_STR) {
    say_error("capi-expirationd: illegal params (task.it_index_iter)");
    return 0;
  }
  uint32_t len;
  const char *str = mp_decode_str(pos, &len);
  if (strncmp(str, "TREE", len) == 0)
    task->it_index_iter = ITER_GT;
  else
    task->it_index_iter = ITER_ALL;
  return 1;
}

static int
parse_it_index(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_MAP) {
    say_error("capi-expirationd: illegal params (task.it_index)");
    return 0;
  }
  uint32_t size = mp_decode_map(pos);
  for (uint32_t i = 0; i < size; ++i) {
    if (mp_typeof(**pos) == MP_STR) {
      uint32_t len;
      const char *str = mp_decode_str(pos, &len);
      if (strncmp(str, "id", len) == 0) {
        if (!parse_it_index_id(task, pos))
          return 0;
      } else if (strncmp(str, "type", len) == 0) {
        if (!parse_it_index_iter(task, pos))
          return 0;
      } else
        mp_next(pos);
    } else
      mp_next(pos);
  }
  return 1;
}

static int
parse_field_no(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT) {
    say_error("capi-expirationd: illegal params (task.field_no)");
    return 0;
  }
  task->field_no = mp_decode_uint(pos);
  if (task->field_no == 0) {
    say_error("capi-expirationd: illegal params (task.field_no)");
    return 0;
  }
  return 1;
}

static int
parse_scan_tuples_per_it(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT) {
    say_error("capi-expirationd: illegal params (task.scan_tuples_for_it)");
    return 0;
  }
  task->scan_tuples_per_it = mp_decode_uint(pos);
  return 1;
}

static int
parse_scan_time(struct fiber_task *task, const char **pos)
{
  if (mp_typeof(**pos) != MP_UINT) {
    say_error("capi-expirationd: illegal params (task.scan_time)");
    return 0;
  }
  task->scan_time = mp_decode_uint(pos);
  return 1;
}

API_EXPORT int
start(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
  struct fiber_task *task = task_alloc();
  if (mp_typeof(*args) != MP_ARRAY || mp_decode_array(&args) != 7) {
    say_error("capi-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  if (!parse_name(task, &args) ||
      !parse_space_id(task, &args) ||
      !parse_rm_index(task, &args) ||
      !parse_it_index(task, &args) ||
      !parse_field_no(task, &args) ||
      !parse_scan_tuples_per_it(task, &args) ||
      !parse_scan_time(task, &args)) {
    free(task);
    return ER_ILLEGAL_PARAMS;
  }
  task->fiber = fiber_new(task->name, &work);
  fiber_set_joinable(task->fiber, 1);
  task->next = task_list;
  task_list = task;
  fiber_start(task->fiber, task);
  return 0;
}

API_EXPORT int
kill(box_function_ctx_t *ctx, const char *args, const char *args_end)
{
  struct fiber_task *task = task_alloc();
  if (mp_typeof(*args) != MP_ARRAY || mp_decode_array(&args) != 1) {
    say_error("capi-expirationd: illegal params");
    return ER_ILLEGAL_PARAMS;
  }
  if (!parse_name(task, &args)) {
    free(task);
    return ER_ILLEGAL_PARAMS;
  }
  struct fiber_task *found = task_find(task->name);
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
