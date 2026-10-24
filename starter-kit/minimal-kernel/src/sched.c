// sched.c — Minimal Round-Robin Scheduler

#include "sched.h"
#include "uart.h"

static task_t tasks[MAX_TASKS];
static int num_tasks = 0;
static int current_task = -1;
static void (*task_entry[MAX_TASKS])(void);
static context_t boot_ctx;  // context of kernel_main, saved on first switch

// Defined in assembly — switches callee-saved registers
extern void context_switch(context_t *old, context_t *new);

// Assembly for context switch (inline for simplicity)
asm(
    ".globl context_switch\n"
    "context_switch:\n"
    "   sd ra,  0(a0)\n"
    "   sd sp,  8(a0)\n"
    "   sd s0, 16(a0)\n"
    "   sd s1, 24(a0)\n"
    "   sd s2, 32(a0)\n"
    "   sd s3, 40(a0)\n"
    "   sd s4, 48(a0)\n"
    "   sd s5, 56(a0)\n"
    "   sd s6, 64(a0)\n"
    "   sd s7, 72(a0)\n"
    "   sd s8, 80(a0)\n"
    "   sd s9, 88(a0)\n"
    "   sd s10,96(a0)\n"
    "   sd s11,104(a0)\n"
    "   ld ra,  0(a1)\n"
    "   ld sp,  8(a1)\n"
    "   ld s0, 16(a1)\n"
    "   ld s1, 24(a1)\n"
    "   ld s2, 32(a1)\n"
    "   ld s3, 40(a1)\n"
    "   ld s4, 48(a1)\n"
    "   ld s5, 56(a1)\n"
    "   ld s6, 64(a1)\n"
    "   ld s7, 72(a1)\n"
    "   ld s8, 80(a1)\n"
    "   ld s9, 88(a1)\n"
    "   ld s10,96(a1)\n"
    "   ld s11,104(a1)\n"
    "   ret\n"
);

static void task_exit(void) {
    uart_printf("[sched] task %d exited\n", current_pid());
    tasks[current_task].state = TASK_DEAD;
    yield();
    // Should never reach here
    while (1) asm volatile("wfi");
}

// First code a new task runs: call its entry, then exit cleanly when it returns.
static void task_trampoline(void) {
    task_entry[current_task]();
    task_exit();
}

void sched_init(void) {
    num_tasks = 0;
    current_task = -1;
}

void task_create(void (*entry)(void), const char *name) {
    if (num_tasks >= MAX_TASKS) {
        uart_printf("[sched] cannot create task '%s': max tasks reached\n", name);
        return;
    }

    task_t *t = &tasks[num_tasks];
    t->pid = num_tasks + 1;
    t->state = TASK_READY;

    // Set up stack: return address = entry, then task_exit as fallback
    uint64_t stack_top = (uint64_t)&t->stack[STACK_SIZE];
    stack_top &= ~0xFUL;  // 16-byte align

    task_entry[num_tasks] = entry;
    t->ctx.sp = stack_top;
    t->ctx.ra = (uint64_t)task_trampoline;
    t->ctx.s0 = 0;

    uart_printf("[sched] created task %d: '%s'\n", t->pid, name);
    num_tasks++;
}

void schedule(void) {
    if (num_tasks == 0) return;

    int prev = current_task;
    // Round-robin: find next ready task
    for (int i = 1; i <= num_tasks; i++) {
        int idx = (current_task + i) % num_tasks;
        if (tasks[idx].state == TASK_READY || tasks[idx].state == TASK_RUNNING) {
            if (prev >= 0 && tasks[prev].state == TASK_RUNNING)
                tasks[prev].state = TASK_READY;

            current_task = idx;
            tasks[idx].state = TASK_RUNNING;

            if (prev >= 0 && prev != idx)
                context_switch(&tasks[prev].ctx, &tasks[idx].ctx);
            else if (prev < 0)
                context_switch(&boot_ctx, &tasks[idx].ctx); // Bootstrap
            return;
        }
    }

    // No ready tasks — halt
    uart_puts("[sched] no runnable tasks, halting\n");
    while (1) asm volatile("wfi");
}

void yield(void) {
    schedule();
}

int current_pid(void) {
    if (current_task < 0) return 0;
    return tasks[current_task].pid;
}
