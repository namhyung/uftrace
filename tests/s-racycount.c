#include <pthread.h>

#define COUNT  10000

static volatile int count;

static void racy_count(pthread_barrier_t *bar)
{
  int i;

  pthread_barrier_wait(bar);

  for (i = 0; i < COUNT; i++)
    count++;
}

static void *thread_fn(void *arg)
{
  racy_count(arg);
  return NULL;
}

int main(void)
{
  pthread_t id[2];
  pthread_barrier_t bar;

  pthread_barrier_init(&bar, NULL, 3);
  pthread_create(&id[0], NULL, thread_fn, &bar);
  pthread_create(&id[1], NULL, thread_fn, &bar);

  racy_count(&bar);

  pthread_join(id[0], NULL);
  pthread_join(id[1], NULL);

  return !(count > 0);
}
