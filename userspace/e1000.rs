//! Ring-3 Intel 82540EM driver. MMIO and pinned DMA grants come from the kernel.
//!
//! Legacy descriptor layout and register behavior are documented by QEMU's
//! device implementation: https://github.com/qemu/qemu/blob/master/hw/net/e1000.c
//! CPU virtual addresses and DMA IOVAs are deliberately different. The kernel
//! owns PCI configuration and a VT-d domain that contains only our DMA pool.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{Ordering, fence};

use crate::syscall;

pub const MAX_FRAME_SIZE: usize = 1514;
const BUFFER_SIZE: usize = 2048;
const RING_SIZE: usize = 64;

const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EERD: usize = 0x0014;
const ICR: usize = 0x00c0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const RDTR: usize = 0x2820;
const RADV: usize = 0x282c;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const TIDV: usize = 0x3820;
const TADV: usize = 0x382c;
const RXCSUM: usize = 0x5000;
const MTA: usize = 0x5200;
const RAL: usize = 0x5400;
const RAH: usize = 0x5404;

const CTRL_RESET: u32 = 1 << 26;
const CTRL_LINK_UP: u32 = 1 << 6;
const CTRL_PHY_RESET: u32 = 1 << 31;
const CTRL_VLAN_MODE: u32 = 1 << 30;
const CTRL_INVERT_LOSS: u32 = 1 << 7;
const STATUS_LINK_UP: u32 = 1 << 1;
const RX_DONE: u8 = 1;
const RX_END_OF_PACKET: u8 = 1 << 1;
const TX_DONE: u8 = 1;
const TX_END_OF_PACKET: u8 = 1;
const TX_INSERT_FCS: u8 = 1 << 1;
const TX_REPORT_STATUS: u8 = 1 << 3;

#[derive(Clone, Copy)]
#[repr(C)]
struct RxDescriptor {
    address: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

impl RxDescriptor {
    const EMPTY: Self = Self {
        address: 0,
        length: 0,
        checksum: 0,
        status: 0,
        errors: 0,
        special: 0,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct TxDescriptor {
    address: u64,
    length: u16,
    checksum_offset: u8,
    command: u8,
    status: u8,
    checksum_start: u8,
    special: u16,
}

impl TxDescriptor {
    const EMPTY: Self = Self {
        address: 0,
        length: 0,
        checksum_offset: 0,
        command: 0,
        status: 0,
        checksum_start: 0,
        special: 0,
    };
}

// Ring bases must be 16-byte aligned and lengths multiples of 128 bytes.
// Each ring occupies 1024 bytes, so both bases in DmaStorage are aligned.
#[repr(C, align(4096))]
struct DmaStorage {
    rx: [RxDescriptor; RING_SIZE],
    tx: [TxDescriptor; RING_SIZE],
    rx_buffers: [[u8; BUFFER_SIZE]; RING_SIZE],
    tx_buffers: [[u8; BUFFER_SIZE]; RING_SIZE],
}

const _: () = {
    assert!(size_of::<RxDescriptor>() == 16);
    assert!(size_of::<TxDescriptor>() == 16);
    assert!(align_of::<DmaStorage>() == 4096);
    assert!(size_of::<DmaStorage>() == 0x41000);
    assert!((size_of::<RxDescriptor>() * RING_SIZE).is_multiple_of(128));
    assert!(core::mem::offset_of!(DmaStorage, tx).is_multiple_of(16));
    assert!(core::mem::offset_of!(RxDescriptor, status) == 12);
    assert!(core::mem::offset_of!(TxDescriptor, status) == 12);
};

pub struct E1000 {
    mmio: usize,
    dma: *mut DmaStorage,
    iova: u64,
    mac: [u8; 6],
    rx_next: usize,
    tx_next: usize,
    rx_discarding: bool,
}

impl E1000 {
    pub fn init(mmio: u64, dma: u64, iova: u64, requested_mac: u64) -> Result<Self, &'static str> {
        // The kernel passes a validated administrative override, or zero on
        // first boot. Validate again before touching the NIC's registers.
        let requested_mac = if requested_mac == 0 {
            None
        } else {
            let bytes: [u8; 6] = requested_mac.to_le_bytes()[..6].try_into().unwrap();
            if requested_mac >> 48 != 0 || !valid_mac(bytes) {
                return Err("invalid configured NIC MAC address");
            }
            Some(bytes)
        };
        let valid_iova = iova
            .checked_sub(crate::abi::DRIVER_IOVA)
            .is_some_and(|offset| {
                offset.is_multiple_of(crate::abi::DRIVER_IOVA_STRIDE)
                    && offset / crate::abi::DRIVER_IOVA_STRIDE
                        < crate::abi::MAX_NIC_INTERFACES as u64
            });
        if mmio != crate::abi::DRIVER_MMIO || dma != crate::abi::DRIVER_DMA || !valid_iova {
            return Err("invalid NIC capability addresses");
        }
        let mut nic = Self {
            mmio: mmio as usize,
            dma: dma as *mut DmaStorage,
            iova,
            mac: [0; 6],
            rx_next: 0,
            tx_next: 0,
            rx_discarding: false,
        };
        nic.write(IMC, u32::MAX);
        nic.write(RCTL, 0);
        nic.write(TCTL, 0);
        nic.read(STATUS); // Flush posted MMIO writes before reset.
        delay(10);
        nic.write(CTRL, nic.read(CTRL) | CTRL_RESET);
        let deadline = syscall::now_millis() + 100;
        while nic.read(CTRL) & CTRL_RESET != 0 {
            if syscall::now_millis() >= deadline {
                return Err("e1000 reset timed out");
            }
            core::hint::spin_loop();
        }
        delay(10);
        nic.write(IMC, u32::MAX);
        nic.read(ICR);
        nic.reset_phy()?;
        nic.mac = match requested_mac {
            Some(mac) => mac,
            None => nic.read_mac()?,
        };
        nic.write(RAL, u32::from_le_bytes(nic.mac[..4].try_into().unwrap()));
        nic.write(
            RAH,
            u32::from(u16::from_le_bytes([nic.mac[4], nic.mac[5]])) | (1 << 31),
        );
        // Remove any firmware secondary unicast/multicast filters.
        for index in 1..16 {
            nic.write(RAL + index * 8, 0);
            nic.write(RAH + index * 8, 0);
        }
        for index in 0..128 {
            nic.write(MTA + index * 4, 0);
        }
        nic.write(
            CTRL,
            (nic.read(CTRL) | CTRL_LINK_UP) & !(CTRL_PHY_RESET | CTRL_VLAN_MODE | CTRL_INVERT_LOSS),
        );

        // SAFETY: the driver exclusively owns its grant and DMA is still disabled,
        // and all indices are in bounds. Raw pointers create no Rust references
        // to descriptor memory subsequently shared with the device.
        unsafe {
            for index in 0..RING_SIZE {
                let rx_address = nic.dma_address(addr_of!((*nic.dma).rx_buffers[index]) as usize);
                addr_of_mut!((*nic.dma).rx[index]).write_volatile(RxDescriptor {
                    address: rx_address,
                    ..RxDescriptor::EMPTY
                });
                let tx_address = nic.dma_address(addr_of!((*nic.dma).tx_buffers[index]) as usize);
                addr_of_mut!((*nic.dma).tx[index]).write_volatile(TxDescriptor {
                    address: tx_address,
                    status: TX_DONE,
                    ..TxDescriptor::EMPTY
                });
            }
            nic.write(
                RDBAL,
                nic.dma_address(addr_of!((*nic.dma).rx) as usize) as u32,
            );
            nic.write(RDBAH, 0);
            nic.write(
                TDBAL,
                nic.dma_address(addr_of!((*nic.dma).tx) as usize) as u32,
            );
            nic.write(TDBAH, 0);
        }
        nic.write(RDLEN, (RING_SIZE * size_of::<RxDescriptor>()) as u32);
        nic.write(RDH, 0);
        nic.write(RDT, (RING_SIZE - 1) as u32);
        nic.write(TDLEN, (RING_SIZE * size_of::<TxDescriptor>()) as u32);
        nic.write(TDH, 0);
        nic.write(TDT, 0);
        nic.write(RDTR, 0);
        nic.write(RADV, 0);
        nic.write(TIDV, 0);
        nic.write(TADV, 0);
        nic.write(RXCSUM, 0); // The IP/TCP stack verifies all checksums.
        // Copper defaults: IPGT=10, IPGR1=8, IPGR2=6.
        nic.write(TIPG, 10 | (8 << 10) | (6 << 20));
        fence(Ordering::Release);
        // EN | PSP | collision threshold=15 | collision distance=64.
        nic.write(TCTL, (1 << 1) | (1 << 3) | (15 << 4) | (64 << 12));
        // EN | BAM | SECRC, 2048-byte buffers, ordinary frames, no loopback.
        nic.write(RCTL, (1 << 1) | (1 << 15) | (1 << 26));
        nic.read(STATUS);
        Ok(nic)
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        self.read(STATUS) & STATUS_LINK_UP != 0
    }

    /// Copy one complete untagged Ethernet frame, without FCS, into `packet`.
    /// Invalid or split frames are drained through EOP, including across calls.
    pub fn receive(&mut self, packet: &mut [u8]) -> Option<usize> {
        for _ in 0..RING_SIZE {
            let index = self.rx_next;
            // SAFETY: the private index is always in bounds. Read only status
            // until DD transfers descriptor and buffer ownership to the CPU.
            let descriptor = unsafe { addr_of_mut!((*self.dma).rx[index]) };
            let status = unsafe { addr_of!((*descriptor).status).read_volatile() };
            if status & RX_DONE == 0 {
                return None;
            }
            fence(Ordering::Acquire);
            // SAFETY: after DD and the acquire fence the NIC will not alter
            // this descriptor/buffer until we publish the recycled tail.
            let completed = unsafe { descriptor.read_volatile() };
            let length = usize::from(completed.length);
            let end = status & RX_END_OF_PACKET != 0;
            let valid = end
                && !self.rx_discarding
                && completed.errors == 0
                && (14..=MAX_FRAME_SIZE).contains(&length)
                && length <= packet.len();
            self.rx_discarding = !end;
            if valid {
                // SAFETY: length is bounded by both buffers, the granted DMA
                // buffer cannot alias the caller's slice, and DD grants CPU
                // ownership until the tail write below.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        addr_of!((*self.dma).rx_buffers[index]).cast::<u8>(),
                        packet.as_mut_ptr(),
                        length,
                    );
                }
            }
            // SAFETY: we still own this descriptor. Clear all writeback fields
            // before the release fence and RDT return it to hardware.
            unsafe {
                descriptor.write_volatile(RxDescriptor {
                    address: self.dma_address(addr_of!((*self.dma).rx_buffers[index]) as usize),
                    ..RxDescriptor::EMPTY
                });
            }
            fence(Ordering::Release);
            self.write(RDT, index as u32);
            self.rx_next = (index + 1) % RING_SIZE;
            if valid {
                return Some(length);
            }
        }
        None
    }

    pub fn can_transmit(&self) -> bool {
        // Keep one ring entry unused: TDT == TDH must always mean empty.
        if (self.tx_next + 1) % RING_SIZE == self.read(TDH) as usize {
            return false;
        }
        // SAFETY: the bounded index selects a permanently allocated descriptor.
        // Only hardware writes status while this descriptor is in flight.
        let status = unsafe { addr_of!((*self.dma).tx[self.tx_next].status).read_volatile() };
        status & TX_DONE != 0
    }

    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if !(14..=MAX_FRAME_SIZE).contains(&frame.len()) {
            return Err("e1000 transmit frame length is outside 14..1514 bytes");
        }
        if !self.can_transmit() {
            return Err("e1000 transmit ring is full");
        }
        fence(Ordering::Acquire);
        let index = self.tx_next;
        // SAFETY: DD has returned this descriptor/buffer to the CPU, and the
        // single owner cannot enqueue a second frame concurrently. The source
        // does not alias granted DMA memory and its length fits BUFFER_SIZE.
        unsafe {
            let buffer = addr_of_mut!((*self.dma).tx_buffers[index]).cast::<u8>();
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
            addr_of_mut!((*self.dma).tx[index]).write_volatile(TxDescriptor {
                address: self.dma_address(buffer as usize),
                length: frame.len() as u16,
                command: TX_END_OF_PACKET | TX_INSERT_FCS | TX_REPORT_STATUS,
                ..TxDescriptor::EMPTY
            });
        }
        // x86 DMA is cache coherent; the release fence orders buffer and
        // descriptor writes before the uncached MMIO doorbell. The device
        // retains ownership until its next DD writeback, never merely TDH.
        fence(Ordering::Release);
        self.tx_next = (index + 1) % RING_SIZE;
        self.write(TDT, self.tx_next as u32);
        Ok(())
    }

    fn reset_phy(&self) -> Result<(), &'static str> {
        // QEMU CTRL.RST does not reset PHY registers. Restore full duplex,
        // 1000 Mbps/autonegotiation and clear loopback, powerdown and isolate.
        self.write(0x20, (1 << 26) | (1 << 21) | 0x1140);
        let deadline = syscall::now_millis() + 100;
        while self.read(0x20) & (1 << 28) == 0 {
            if syscall::now_millis() >= deadline {
                return Err("PHY restore timed out");
            }
            syscall::poll();
        }
        if self.read(0x20) & (1 << 30) != 0 {
            return Err("PHY restore failed");
        }
        Ok(())
    }

    fn read_mac(&self) -> Result<[u8; 6], &'static str> {
        // RAL/RAH are writable by the previous driver incarnation. QEMU's
        // immutable EEPROM retains the assigned MAC across driver restarts.
        let mut mac = [0; 6];
        for word in 0..3 {
            self.write(EERD, 1 | ((word as u32) << 8));
            let deadline = syscall::now_millis() + 100;
            let value = loop {
                let value = self.read(EERD);
                if value & (1 << 4) != 0 {
                    break value;
                }
                if syscall::now_millis() >= deadline {
                    return Err("e1000 EEPROM read timed out");
                }
                syscall::poll();
            };
            mac[word * 2] = (value >> 16) as u8;
            mac[word * 2 + 1] = (value >> 24) as u8;
        }
        if !valid_mac(mac) {
            return Err("e1000 has no valid unicast MAC address");
        }
        Ok(mac)
    }

    /// Deliberately issue a DMA read outside the grant for the isolation test.
    #[cfg(driver_test)]
    pub fn probe_forbidden_read(&mut self) {
        // SAFETY: this test intentionally programs an illegal IOVA, not an
        // invalid CPU pointer. VT-d must fault it before any memory is read.
        unsafe {
            addr_of_mut!((*self.dma).tx[0]).write_volatile(TxDescriptor {
                address: crate::abi::KERNEL_PROBE_ADDRESS,
                length: 60,
                command: TX_END_OF_PACKET | TX_INSERT_FCS | TX_REPORT_STATUS,
                ..TxDescriptor::EMPTY
            });
        }
        fence(Ordering::Release);
        self.write(TDT, 1);
    }

    /// PHY loopback makes the write probe independent of incoming host traffic.
    /// A forbidden RAM destination must fault; the MSI aperture probe must not
    /// deliver NMI/INIT/SMI on the explicitly APIC-less QEMU target.
    #[cfg(driver_test)]
    pub fn probe_dma_write(&mut self, target: u64) -> Result<(), &'static str> {
        self.write(RCTL, 0);
        self.read(STATUS);
        // A dedicated test MAC excludes host traffic during the probe. Its
        // bytes match the first six bytes of the NMI/INIT test payload below.
        self.write(RAL, 0x0000_0400);
        self.write(RAH, (1 << 31) | 0x0500);
        // SAFETY: reception is stopped; reclaim the first descriptor and reset
        // the hardware head. This prevents unrelated earlier packets from
        // masquerading as a completed malicious write.
        unsafe {
            addr_of_mut!((*self.dma).rx[0]).write_volatile(RxDescriptor {
                address: target,
                ..RxDescriptor::EMPTY
            });
        }
        fence(Ordering::Release);
        self.write(RDH, 0);
        self.write(RDT, 1);
        self.write(RCTL, (1 << 1) | (1 << 26));
        self.write(0x20, (1 << 26) | (1 << 21) | (1 << 14));
        let deadline = syscall::now_millis() + 100;
        while self.read(0x20) & (1 << 28) == 0 {
            if syscall::now_millis() >= deadline {
                return Err("PHY loopback setup timed out");
            }
            syscall::poll();
        }
        if self.read(0x20) & (1 << 30) != 0 {
            return Err("PHY loopback setup failed");
        }
        // QEMU delays reception for 1 second after an RCTL update.
        delay(1100);
        let mut frame = [0u8; 60];
        for (index, chunk) in frame.chunks_exact_mut(4).enumerate() {
            let msi: u32 = match index % 3 {
                0 => 0x400,
                1 => 0x500,
                _ => 0x200,
            };
            chunk.copy_from_slice(&msi.to_le_bytes());
        }
        self.transmit(&frame)?;
        let deadline = syscall::now_millis() + 100;
        loop {
            // SAFETY: read only the status of our permanently mapped RX slot.
            let status = unsafe { addr_of!((*self.dma).rx[0].status).read_volatile() };
            if status & RX_DONE != 0 {
                break;
            }
            if syscall::now_millis() >= deadline {
                return Err("DMA write probe did not complete");
            }
            syscall::poll();
        }
        Ok(())
    }

    fn dma_address(&self, pointer: usize) -> u64 {
        self.iova + (pointer - self.dma as usize) as u64
    }

    fn read(&self, register: usize) -> u32 {
        // SAFETY: init validates the kernel-provided uncached BAR grant.
        // All private callers supply aligned offsets inside its 128 KiB range.
        unsafe { ((self.mmio + register) as *const u32).read_volatile() }
    }

    fn write(&self, register: usize, value: u32) {
        // SAFETY: the same validated BAR bounds/alignment as read apply, and
        // the unique E1000 owns this device's register programming.
        unsafe { ((self.mmio + register) as *mut u32).write_volatile(value) }
    }
}

fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

fn delay(milliseconds: i64) {
    let deadline = syscall::now_millis() + milliseconds;
    while syscall::now_millis() < deadline {
        syscall::poll();
    }
}
