#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TASKS 64
#define LABEL_LEN 64

typedef struct Task {
    int id;
    char label[LABEL_LEN];
    int priority;
    int completed;
} Task;

typedef struct TaskList {
    Task **items;
    int count;
    int capacity;
} TaskList;

typedef void (*TaskCallback)(Task *);

typedef struct Notification {
    Task *target;
    TaskCallback on_complete;
} Notification;

static Notification pending_notifications[MAX_TASKS];
static int notification_count = 0;

static TaskList *create_task_list(int capacity) {
    TaskList *list = (TaskList *)malloc(sizeof(TaskList));
    if (!list) return NULL;
    list->items = (Task **)calloc(capacity, sizeof(Task *));
    list->count = 0;
    list->capacity = capacity;
    return list;
}

static Task *create_task(int id, const char *label, int priority) {
    Task *t = (Task *)malloc(sizeof(Task));
    if (!t) return NULL;
    t->id = id;
    strncpy(t->label, label, LABEL_LEN - 1);
    t->label[LABEL_LEN - 1] = '\0';
    t->priority = priority;
    t->completed = 0;
    return t;
}

static int add_task(TaskList *list, Task *task) {
    if (list->count >= list->capacity) return -1;
    list->items[list->count] = task;
    list->count++;
    return 0;
}

static void notify_on_complete(Task *task, TaskCallback cb) {
    if (notification_count >= MAX_TASKS) return;
    pending_notifications[notification_count].target = task;
    pending_notifications[notification_count].on_complete = cb;
    notification_count++;
}

static void fire_notifications(void) {
    for (int i = 0; i < notification_count; i++) {
        Notification *n = &pending_notifications[i];
        if (n->target && n->on_complete) {
            n->on_complete(n->target);
        }
    }
    notification_count = 0;
}

static void print_task_status(Task *task) {
    printf("  Task %d [%s]: priority=%d completed=%d\n",
           task->id, task->label, task->priority, task->completed);
}

static void remove_task(TaskList *list, int index) {
    if (index < 0 || index >= list->count) return;
    free(list->items[index]);
    for (int i = index; i < list->count - 1; i++) {
        list->items[i] = list->items[i + 1];
    }
    list->count--;
}

static Task *find_task_by_id(TaskList *list, int id) {
    for (int i = 0; i < list->count; i++) {
        if (list->items[i]->id == id) {
            return list->items[i];
        }
    }
    return NULL;
}

static void complete_and_remove(TaskList *list, int id) {
    Task *task = find_task_by_id(list, id);
    if (!task) return;

    task->completed = 1;
    printf("Completed task %d: %s\n", task->id, task->label);

    for (int i = 0; i < list->count; i++) {
        if (list->items[i]->id == id) {
            remove_task(list, i);
            break;
        }
    }

    printf("Post-removal check: task %d label = %s\n", task->id, task->label);
}

static char *build_summary(TaskList *list) {
    size_t buf_size = 128;
    char *summary = (char *)malloc(buf_size);
    if (!summary) return NULL;

    int offset = snprintf(summary, buf_size, "Tasks: %d items\n", list->count);

    for (int i = 0; i < list->count; i++) {
        int needed = snprintf(NULL, 0, "  [%d] %s (p=%d)\n",
                              list->items[i]->id,
                              list->items[i]->label,
                              list->items[i]->priority);

        if (offset + needed + 1 > (int)buf_size) {
            buf_size = (offset + needed + 1) * 2;
            char *old = summary;
            summary = (char *)realloc(old, buf_size);
            if (!summary) {
                printf("Realloc result for old pointer: %p\n", (void *)old);
                free(old);
                return NULL;
            }
        }

        offset += snprintf(summary + offset, buf_size - offset,
                           "  [%d] %s (p=%d)\n",
                           list->items[i]->id,
                           list->items[i]->label,
                           list->items[i]->priority);
    }

    return summary;
}

static void duplicate_and_free(TaskList *list) {
    if (list->count == 0) return;

    Task *original = list->items[0];
    Task *copy = (Task *)malloc(sizeof(Task));
    if (!copy) return;
    memcpy(copy, original, sizeof(Task));

    free(original);
    free(original);

    list->items[0] = copy;
    printf("Duplicated task: %s\n", copy->label);
}

static void archive_tasks(TaskList *list) {
    Task *archived[MAX_TASKS];
    int archived_count = 0;

    for (int i = 0; i < list->count; i++) {
        if (list->items[i]->completed) {
            archived[archived_count++] = list->items[i];
        }
    }

    for (int i = list->count - 1; i >= 0; i--) {
        if (list->items[i]->completed) {
            free(list->items[i]);
            for (int j = i; j < list->count - 1; j++) {
                list->items[j] = list->items[j + 1];
            }
            list->count--;
        }
    }

    printf("Archived tasks:\n");
    for (int i = 0; i < archived_count; i++) {
        printf("  [%d] %s\n", archived[i]->id, archived[i]->label);
    }
}

static void destroy_task_list(TaskList *list) {
    for (int i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    free(list);
}

static void run_demo(const char *mode) {
    TaskList *list = create_task_list(MAX_TASKS);
    if (!list) return;

    add_task(list, create_task(1, "design_schema", 3));
    add_task(list, create_task(2, "implement_api", 5));
    add_task(list, create_task(3, "write_tests", 2));
    add_task(list, create_task(4, "deploy_staging", 4));
    add_task(list, create_task(5, "review_code", 1));

    if (strcmp(mode, "complete") == 0) {
        complete_and_remove(list, 2);
    } else if (strcmp(mode, "notify") == 0) {
        notify_on_complete(list->items[0], print_task_status);
        notify_on_complete(list->items[1], print_task_status);
        remove_task(list, 0);
        remove_task(list, 0);
        printf("Firing notifications for removed tasks:\n");
        fire_notifications();
    } else if (strcmp(mode, "summary") == 0) {
        char *s = build_summary(list);
        if (s) {
            printf("%s", s);
            free(s);
        }
    } else if (strcmp(mode, "duplicate") == 0) {
        duplicate_and_free(list);
    } else if (strcmp(mode, "archive") == 0) {
        list->items[1]->completed = 1;
        list->items[3]->completed = 1;
        archive_tasks(list);
    } else {
        printf("Unknown mode: %s\n", mode);
    }

    destroy_task_list(list);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <mode>\n", argv[0]);
        printf("Modes:\n");
        printf("  complete    Complete and remove a task\n");
        printf("  notify      Register and fire task notifications\n");
        printf("  summary     Build task summary with realloc\n");
        printf("  duplicate   Duplicate first task entry\n");
        printf("  archive     Archive completed tasks\n");
        return 0;
    }

    run_demo(argv[1]);
    return 0;
}
