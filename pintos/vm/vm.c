/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include <string.h>

/* 현재 사용중인 프레임을 저장하기 위한 list */
static struct list frame_list;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	list_init (&frame_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static void vm_free_frame (struct frame *frame);
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

static unsigned page_hash_func(const struct hash_elem *e, void *aux);
static bool page_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *new_page = NULL;
	vm_initializer *page_init = NULL;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		switch (VM_TYPE(type)) {
			case VM_ANON:
				page_init = anon_initializer;
				break;
			case VM_FILE:
				page_init = file_backed_initializer;
				break;
		}

		new_page = malloc (sizeof (struct page));
		if (new_page == NULL)
			goto err;

		uninit_new (new_page, upage, init, type, aux, page_init);
		new_page->is_writable = writable;

		if (!spt_insert_page (spt, new_page))
			goto err;

		return true;
	}
err:
	if (new_page != NULL)
		free (new_page);
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *temp_page = NULL;
	struct hash_elem *page_elem = NULL;

	temp_page = malloc (sizeof (struct page));
	if (temp_page == NULL)
		return NULL;

	temp_page->va = pg_round_down (va);
	page_elem = hash_find (&spt->hash, &temp_page->hash_elem);
	free (temp_page);

	if (page_elem != NULL)
		return hash_entry (page_elem, struct page, hash_elem);
	else
		return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	if (!hash_insert (&spt->hash, &page->hash_elem))
		return true;
	else
		return false;
}

/* vm 끝까지 안쓴다면, 함수 삭제 */
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete (&spt->hash, &page->hash_elem);
	vm_free_frame (page->frame);
	vm_dealloc_page (page);
}

/* 들어오는 frame을 free 해주는 함수 */
static void
vm_free_frame (struct frame *frame) {
	if (frame != NULL) {
		list_remove (&frame->elem);
		free (frame);
	}
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	uint8_t *kpage;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage == NULL) {
		// 실패할 경우, 프레임을 evict 해야함
	}

	frame = malloc (sizeof (struct frame));
	if (frame == NULL) PANIC("frame malloc failed");

	list_push_back (&frame_list, &frame->elem);
	frame->kva = kpage;
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr UNUSED) {
	if (!vm_alloc_page_with_initializer (VM_ANON | VM_MARKER_STACK, addr, true, NULL, NULL))
		return false;
	return true;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct thread *curr = thread_current ();
	struct supplemental_page_table *spt = &curr->spt;
	struct page *page = NULL;

	if (addr == NULL || is_kernel_vaddr (addr))
		return false;

	if (not_present == false) {
        // cow 기능 구현하기. 지금은 무조건 false
        return false;
    }
	
	if ((page = spt_find_page (spt, addr)) != NULL) {
		if (page->is_writable == false && write == true)
			return false;
		else
			return vm_do_claim_page (page);
	}

	if (user == true && addr == (curr->user_rsp - 8) && addr >= USER_STACK_MAX) {
		curr->stack_bottom -= PGSIZE;
		return vm_stack_growth (curr->stack_bottom);
	}

	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct thread *curr = thread_current ();
	struct page *page = spt_find_page (&curr->spt, va);

	if (page == NULL)
		return false;
	else
		return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *curr = thread_current ();
	struct frame *frame = vm_get_frame ();

	frame->page = page;
	page->frame = frame;

	if (pml4_get_page (curr->pml4, page->va) != NULL)
		return false;
	
	if (!pml4_set_page (curr->pml4, page->va, frame->kva, page->is_writable))
		return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	if (!hash_init (&spt->hash, page_hash_func, page_less_func, NULL)) {
		PANIC("SPT hash initialization failed");
	}
}

static unsigned
page_hash_func (const struct hash_elem *e, void *aux UNUSED) {
	const struct page *e_page = hash_entry (e, struct page, hash_elem);
	
  	return hash_bytes (&e_page->va, sizeof e_page->va);
}

static bool
page_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
	const struct page *a_page = hash_entry (a, struct page, hash_elem);
  	const struct page *b_page = hash_entry (b, struct page, hash_elem);

  	return a_page->va < b_page->va;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
	bool success = false;

    hash_first(&i, &src->hash);
    while(hash_next(&i)){
		struct page *parent_page = hash_entry (hash_cur(&i), struct page, hash_elem);
		void *parent_va = parent_page->va;
		bool parent_writable = parent_page->is_writable;

		switch (parent_page->operations->type) {
			case VM_UNINIT:
				enum vm_type lazy_type = parent_page->uninit.type;
				vm_initializer *parent_init = parent_page->uninit.init;
				void *parent_aux;

				parent_aux = malloc(sizeof (struct load_arg));
				if (parent_aux == NULL) PANIC("hash_duplicate_page_aux malloc failed");
				memcpy(parent_aux, parent_page->uninit.aux, sizeof (struct load_arg));

				if (!vm_alloc_page_with_initializer (lazy_type, parent_va, parent_writable, parent_init, parent_aux)) {
					free (parent_aux);
					goto done;
				}
				break;
			default:	//file 타입 spt까지 쓰게 된다면, default 지우고 각각 switch 하기
				enum vm_type parent_type = parent_page->operations->type;
				struct page *curr_page = NULL;

				if (!vm_alloc_page_with_initializer (parent_type, parent_va, parent_writable, NULL, NULL))
					goto done;

				if ((curr_page = spt_find_page (dst, parent_va)) == NULL || !vm_do_claim_page (curr_page))
					goto done;
				
				memcpy(curr_page->frame->kva, parent_page->frame->kva, PGSIZE);
				break;
		}
    }

	success = true;
done:
    return success;
}

static void
hash_delete_page (struct hash_elem *e, void *aux) {
	struct page *delete_page = hash_entry (e, struct page, hash_elem);
	vm_free_frame (delete_page->frame);
	vm_dealloc_page (delete_page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	hash_clear (&spt->hash, hash_delete_page);
}
