/*
 *  Copyright (C) 2014-17 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _LIST_H_
#define _LIST_H_

typedef struct list_head list_head_t;

struct list_head {
  list_head_t *next, *prev;
};

#define list_head_init(list) {			\
  (list)->next = (list)->prev = (list);		\
}

#define list_add(new, head) {			\
  (head)->next->prev = (new);			\
  (new) ->next =       (head)->next;		\
  (new) ->prev =       (head);			\
  (head)->next =       (new);			\
}

#define list_add_tail(new, head) {		\
  (new) ->next =       (head);			\
  (new) ->prev =       (head)->prev;		\
  (head)->prev->next = (new);			\
  (head)->prev =       (new);			\
}

#define list_del(entry) {			\
  (entry)->next->prev = (entry)->prev;		\
  (entry)->prev->next = (entry)->next;		\
  (entry)->next =       (entry)->prev = NULL;	\
}

#define list_empty(head) ((head)->next == (head))

#define list_foreach(e, n, h) for (e = (h)->next, n = e->next; e != (h); e = n, n = e->next)

#define list_entry(p, t, f) ({ const typeof(((t *)0)->f) *__f_p = (p); (t *) ((char *) __f_p - ((size_t) &((t *)0)->f)); })

#endif /* _LIST_H_ */

