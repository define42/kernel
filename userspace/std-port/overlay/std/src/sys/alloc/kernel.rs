use crate::alloc::{GlobalAlloc, Layout, System};

unsafe extern "C" {
    fn __kernel_std_alloc(size: usize, align: usize) -> *mut u8;
    fn __kernel_std_alloc_zeroed(size: usize, align: usize) -> *mut u8;
    fn __kernel_std_dealloc(ptr: *mut u8, size: usize, align: usize);
    fn __kernel_std_realloc(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8;
}

// These shims call the process-local allocator directly, never the global
// allocator dispatcher (which could otherwise recurse back into System).
#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { __kernel_std_alloc(layout.size(), layout.align()) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { __kernel_std_alloc_zeroed(layout.size(), layout.align()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { __kernel_std_dealloc(ptr, layout.size(), layout.align()) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { __kernel_std_realloc(ptr, layout.size(), layout.align(), new_size) }
    }
}
