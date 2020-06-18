#ifndef TLB_H
#define TLB_H

#include <string.h>
#include "emu/memory.h"
#include "debug.h"

#include "kernel/task.h"

#include "brads.h"

struct tlb_entry {
    page_t page;
    page_t page_if_writable;
    uintptr_t data_minus_addr;
};
#define TLB_BITS 10
#define TLB_SIZE (1 << TLB_BITS)
struct tlb {
    struct mem *mem;
    page_t dirty_page;
    struct tlb_entry entries[TLB_SIZE];
};

#define TLB_INDEX(addr) (((addr >> PAGE_BITS) & (TLB_SIZE - 1)) ^ (addr >> (PAGE_BITS + TLB_BITS)))
#define TLB_PAGE(addr) (addr & 0xfffff000)
#define TLB_PAGE_EMPTY 1
void tlb_init(struct tlb *tlb, struct mem *mem);
void tlb_free(struct tlb *tlb);
void tlb_flush(struct tlb *tlb);
void *tlb_handle_miss(struct tlb *tlb, addr_t addr, int type);

void *bbtlb_read_ptr(struct tlb *tlb, addr_t addr) {
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    if (entry.page == TLB_PAGE(addr)) {
        void *address = (void *) (entry.data_minus_addr + addr);
        postulate(address != NULL);
        return address;
    }
    return tlb_handle_miss(tlb, addr, MEM_READ);
}


forceinline __no_instrument void *__tlb_read_ptr(struct tlb *tlb, addr_t addr) {
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    if (entry.page == TLB_PAGE(addr)) {
        void *address = (void *) (entry.data_minus_addr + addr);
        postulate(address != NULL);
        return address;
    }
    return tlb_handle_miss(tlb, addr, MEM_READ);
}
bool __tlb_read_cross_page(struct tlb *tlb, addr_t addr, char *out, unsigned size);



bool bbtlb_read(struct tlb *tlb, addr_t addr, void *out, unsigned size) {
    if (addr == 0xffffbda8) {
        int d = 3;
    }
    if (PGOFFSET(addr) > PAGE_SIZE - size)
        return __tlb_read_cross_page(tlb, addr, out, size);
    void *ptr = __tlb_read_ptr(tlb, addr);
    if (ptr == NULL)
        return false;
    memcpy(out, ptr, size);
    return true;
}




forceinline __no_instrument bool tlb_read(struct tlb *tlb, addr_t addr, void *out, unsigned size) {
    if (addr == 0xffffbda8) {
        int d = 3;
    }
    if (PGOFFSET(addr) > PAGE_SIZE - size)
        return __tlb_read_cross_page(tlb, addr, out, size);
    void *ptr = __tlb_read_ptr(tlb, addr);
    if (ptr == NULL)
        return false;
    memcpy(out, ptr, size);
    return true;
}

forceinline __no_instrument void *__tlb_write_ptr(struct tlb *tlb, addr_t addr) {
    struct pt_entry *pte = mem_pt(current->mem, PAGE(addr));
    
    char *dbgStr = "";
    
    if (pte && pte->data) {
        dbgStr = pte->data->debugString;
    }
//    if (current->cpu.instructionCount > 100) {
//        printf("DEBUGSTRING: %s\n", dbgStr);
//    }
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    if (entry.page_if_writable == TLB_PAGE(addr)) {
        tlb->dirty_page = TLB_PAGE(addr);
        void *address = (void *) (entry.data_minus_addr + addr);
        postulate(address != NULL);
        return address;
    }
    return tlb_handle_miss(tlb, addr, MEM_WRITE);
}
bool __tlb_write_cross_page(struct tlb *tlb, addr_t addr, const char *value, unsigned size);
forceinline __no_instrument bool tlb_write(struct tlb *tlb, addr_t addr, const void *value, unsigned size) {
    /*
    // Start debuggin JSON Code
    lock(&bradsdebuglock);
    FILE *fp;
    char filenameStr[1000];
    sprintf(filenameStr, "%sishmemwrite-%d.json", rootsource2, current->pid);
    
    fp = fopen(filenameStr, "a+");

    uint32_t val;

    if (size == 4) {
        val = *(uint32_t *)value;
    } else if (size == 2) {
        val = *(uint16_t *)value;
    } else if (size == 1) {
        val = *(uint8_t *)value;
    }

    fprintf(fp, "{\"pid\": \"%d\", \"insn\": \"%d\", \"addr\": \"%x\", \"size\": \"%d\", \"value\": \"%x\"}\n", current->pid, current->cpu.instructionCount, addr, size, val);
    fclose(fp);
    unlock(&bradsdebuglock);
    // End debuggin JSON Code
    
    */
    
    if (PGOFFSET(addr) > PAGE_SIZE - size)
        return __tlb_write_cross_page(tlb, addr, value, size);
    void *ptr = __tlb_write_ptr(tlb, addr);
    if (ptr == NULL)
        return false;
    memcpy(ptr, value, size);
    return true;
}

#endif
