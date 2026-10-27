//! Independently linked, unprivileged e1000 driver process.
#![no_std]
#![no_main]

#[path = "../abi.rs"]
mod abi;
mod e1000;
#[allow(dead_code)]
mod syscall;

use core::{arch::asm, panic::PanicInfo};

const DRIVER_RX: u64 = 14;
const DRIVER_TX: u64 = 15;
const DRIVER_READY: u64 = 16;
const MAC_REGISTER: u64 = 18;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mmio: u64, dma: u64, iova: u64, mode: u64) -> ! {
    let cs: u16;
    // SAFETY: reading CS is unprivileged.
    unsafe {
        asm!("mov {value:x}, cs", value = out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    assert_eq!(cs & 3, 3);
    let mut nic = match e1000::E1000::init(mmio, dma, iova) {
        Ok(nic) => nic,
        Err(error) => {
            syscall::log(error);
            syscall::exit(1);
        }
    };
    let mut packed = [0; 8];
    packed[..6].copy_from_slice(&nic.mac_address());
    // SAFETY: these calls pass scalars only; the kernel validates the caller's
    // driver capability before publishing a MAC or enabling bus mastering.
    unsafe {
        assert_eq!(
            syscall::raw(MAC_REGISTER, u64::from_le_bytes(packed), 0, 0),
            0
        );
        assert_eq!(syscall::raw(DRIVER_READY, 0, 0, 0), 0);
    }
    syscall::log("e1000 driver: CPL=3, VT-d DMA grant active\n");
    syscall::log(if nic.link_up() {
        "e1000: link up\n"
    } else {
        "e1000: link down\n"
    });
    #[cfg(not(driver_test))]
    let _ = mode;
    #[cfg(driver_test)]
    match mode {
        0 => {}
        1 => {
            nic.probe_forbidden_read();
            loop {
                syscall::poll();
            }
        }
        2 => {
            // SAFETY: intentional user fault checks driver crash containment.
            unsafe {
                asm!("ud2", options(noreturn));
            }
        }
        3 => loop {
            core::hint::spin_loop();
        },
        4 => {
            nic.probe_dma_write(0xfee0_0000)
                .expect("MSI aperture probe");
            syscall::log("Driver interrupt aperture NMI/INIT/SMI probe survived\n");
            syscall::exit(0);
        }
        5 => {
            nic.probe_dma_write(0x0010_0000)
                .expect("forbidden DMA write probe");
            loop {
                syscall::poll();
            }
        }
        _ => syscall::exit(1),
    }

    let mut frame = [0; e1000::MAX_FRAME_SIZE];
    let mut pending = None;
    loop {
        if pending.is_none() {
            pending = nic.receive(&mut frame);
        }
        if let Some(length) = pending {
            // SAFETY: immutable initialized CPU-only frame bytes remain valid
            // throughout the synchronous copy. The kernel never receives a
            // DMA pointer or raw hardware descriptor through this ABI.
            let result =
                unsafe { syscall::raw(DRIVER_RX, frame.as_ptr() as u64, length as u64, 0) };
            if result != abi::EAGAIN {
                pending = None;
            }
        }
        if pending.is_none() && nic.can_transmit() {
            // SAFETY: frame is writable private userspace storage. The bounded
            // kernel queue returns at most the supplied capacity.
            let length = unsafe {
                syscall::raw(DRIVER_TX, frame.as_mut_ptr() as u64, frame.len() as u64, 0)
            };
            if length > 0 {
                nic.transmit(&frame[..length as usize])
                    .expect("reserved driver TX slot");
            }
        }
        syscall::poll();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    syscall::log("User e1000 driver panic\n");
    syscall::exit(1)
}
