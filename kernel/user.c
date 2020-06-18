#include <string.h>
#include "kernel/calls.h"
#include "debug.h"
#include "memory.h"
#include "brads.h"


static int __user_read_task(struct task *task, addr_t addr, void *buf, size_t count) {
    
    //printk("\n  mptr Reading from %x    page  %x    offset  %x \n", addr, PAGE(addr), PGOFFSET(addr));
    
    char *cbuf = (char *) buf;
    addr_t p = addr;
    while (p < addr + count) {
        addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        if (chunk_end > addr + count)
            chunk_end = addr + count;
        const char *ptr = mem_ptr(task->mem, p, MEM_READ);
        if (ptr == NULL)
            return 1;
        memcpy(&cbuf[p - addr], ptr, chunk_end - p);
        p = chunk_end;
    }
    return 0;
}

static int __user_write_task(struct task *task, addr_t addr, const void *buf, size_t count) {
    const char *cbuf = (const char *) buf;
    addr_t p = addr;
    while (p < addr + count) {
        addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        if (chunk_end > addr + count)
            chunk_end = addr + count;
        char *ptr = mem_ptr(task->mem, p, MEM_WRITE);
        if (ptr == NULL)
            return 1;
        memcpy(ptr, &cbuf[p - addr], chunk_end - p);
        p = chunk_end;
    }
    return 0;
}

int user_read_task(struct task *task, addr_t addr, void *buf, size_t count) {
    read_wrlock(&task->mem->lock);
    int res = __user_read_task(task, addr, buf, count);
    read_wrunlock(&task->mem->lock);
    return res;
}

int user_read(addr_t addr, void *buf, size_t count) {
    return user_read_task(current, addr, buf, count);
}

int user_write_task(struct task *task, addr_t addr, const void *buf, size_t count) {
    read_wrlock(&task->mem->lock);
    int res = __user_write_task(task, addr, buf, count);
    read_wrunlock(&task->mem->lock);
    return res;
}

int user_write(addr_t addr, const void *buf, size_t count) {

    // THESE ALL HAPPEN BEFORE THE TASK ACTUALLY STARTS FOR PROGRAM SETUP
//    // Start debuggin JSON Code
//    lock(&bradsdebuglock);
//    FILE *fp;
//    char filenameStr[1000];
//    sprintf(filenameStr, "%sishmemwrite-%d.json", rootsource2, current->pid);
//    
//    fp = fopen(filenameStr, "a+");
//
//    uint32_t val;
//
//    if (count == 4) {
//        val = *(uint32_t *)buf;
//    } else if (count == 2) {
//        val = *(uint16_t *)buf;
//    } else if (count == 1) {
//        val = *(uint8_t *)buf;
//    }
//
//    fprintf(fp, "{\"pid\": \"%d\", \"addr\": \"%x\", \"size\": \"%d\", \"value\": \"%x\"}\n", current->pid, addr, count, val);
//    fclose(fp);
//    unlock(&bradsdebuglock);
//    // End debuggin JSON Code
    
    return user_write_task(current, addr, buf, count);
}

int user_read_string(addr_t addr, char *buf, size_t max) {
    if (addr == 0)
        return 1;
    read_wrlock(&current->mem->lock);
    size_t i = 0;
    while (i < max) {
        if (__user_read_task(current, addr + i, &buf[i], sizeof(buf[i]))) {
            read_wrunlock(&current->mem->lock);
            return 1;
        }
        if (buf[i] == '\0')
            break;
        i++;
    }
    read_wrunlock(&current->mem->lock);
    return 0;
}

int user_write_string(addr_t addr, const char *buf) {
    if (addr == 0)
        return 1;
    read_wrlock(&current->mem->lock);
    size_t i = 0;
    do {
        if (__user_write_task(current, addr + i, &buf[i], sizeof(buf[i]))) {
            read_wrunlock(&current->mem->lock);
            return 1;
        }
        i++;
    } while (buf[i - 1] != '\0');
    read_wrunlock(&current->mem->lock);
    return 0;
}
