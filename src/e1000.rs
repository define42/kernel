//! Polling Intel 82540EM driver (QEMU `-device e1000`, PCI 8086:100e).
//!
//! Legacy descriptor layout and register behavior are documented by QEMU's
//! device implementation: https://github.com/qemu/qemu/blob/master/hw/net/e1000.c
//! The kernel identity-maps RAM below 1 GiB and uncached MMIO from 1 to 4 GiB.
//! DMA uses permanently allocated, coherent x86 RAM; no IOMMU is configured.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering, fence};

use crate::{pci, time::Clock};

pub const MAX_FRAME_SIZE: usize = 1514;
const BUFFER_SIZE: usize = 2048;
const RING_SIZE: usize = 64;
const MMIO_SIZE: usize = 128 * 1024;
const RAM_END: usize = 1 << 30;

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
    assert!((size_of::<RxDescriptor>() * RING_SIZE).is_multiple_of(128));
    assert!(core::mem::offset_of!(DmaStorage, tx).is_multiple_of(16));
    assert!(core::mem::offset_of!(RxDescriptor, status) == 12);
    assert!(core::mem::offset_of!(TxDescriptor, status) == 12);
};

static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut DMA: DmaStorage = DmaStorage {
    rx: [RxDescriptor::EMPTY; RING_SIZE],
    tx: [TxDescriptor::EMPTY; RING_SIZE],
    rx_buffers: [[0; BUFFER_SIZE]; RING_SIZE],
    tx_buffers: [[0; BUFFER_SIZE]; RING_SIZE],
};

/// Unique owner of the NIC and its static DMA storage. Initialization is
/// intentionally one-shot, including on error: DMA memory is never reused by
/// a second device or freed while the first device could still reference it.
pub struct E1000 {
    mmio: usize,
    mac: [u8; 6],
    rx_next: usize,
    tx_next: usize,
    rx_discarding: bool,
}

impl E1000 {
    pub fn init(clock: &Clock) -> Result<Self, &'static str> {
        if CLAIMED.swap(true, Ordering::AcqRel) {
            return Err("e1000 initialization was already attempted");
        }
        let function = pci::find(0x8086, 0x100e).ok_or("Intel 82540EM e1000 NIC not found")?;
        let bar = function.read_u32(0x10);
        if bar & 1 != 0 {
            return Err("e1000 BAR0 is not a memory BAR");
        }
        match (bar >> 1) & 3 {
            0 => {}
            2 if function.read_u32(0x14) == 0 => {}
            2 => return Err("e1000 BAR0 is above the 4 GiB identity map"),
            _ => return Err("e1000 BAR0 has an unsupported memory type"),
        }
        let mmio = (bar & !0xf) as usize;
        if !(RAM_END..=(1usize << 32) - MMIO_SIZE).contains(&mmio)
            || !mmio.is_multiple_of(MMIO_SIZE)
        {
            return Err("e1000 BAR0 is outside the aligned uncached 1..4 GiB MMIO region");
        }
        let dma_address = addr_of_mut!(DMA) as usize;
        if dma_address
            .checked_add(size_of::<DmaStorage>())
            .is_none_or(|end| end > RAM_END)
        {
            return Err("e1000 DMA storage is outside identity-mapped RAM");
        }
        function.prepare_memory();
        let mut nic = Self {
            mmio,
            mac: [0; 6],
            rx_next: 0,
            tx_next: 0,
            rx_discarding: false,
        };
        nic.write(IMC, u32::MAX);
        nic.write(RCTL, 0);
        nic.write(TCTL, 0);
        nic.read(STATUS); // Flush posted MMIO writes before reset.
        clock.delay_micros(10_000)?;
        nic.write(CTRL, nic.read(CTRL) | CTRL_RESET);
        let deadline = clock.now_millis() + 100;
        while nic.read(CTRL) & CTRL_RESET != 0 {
            if clock.now_millis() >= deadline {
                return Err("e1000 reset timed out");
            }
            core::hint::spin_loop();
        }
        clock.delay_micros(10_000)?;
        nic.write(IMC, u32::MAX);
        nic.read(ICR);
        nic.mac = nic.read_mac(clock)?;
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

        // SAFETY: CLAIMED guarantees unique access, the NIC's DMA is disabled,
        // and all indices are in bounds. Raw pointers create no Rust references
        // to descriptor memory subsequently shared with the device.
        unsafe {
            for index in 0..RING_SIZE {
                let rx_address = addr_of_mut!(DMA.rx_buffers[index]) as u64;
                addr_of_mut!(DMA.rx[index]).write_volatile(RxDescriptor {
                    address: rx_address,
                    ..RxDescriptor::EMPTY
                });
                let tx_address = addr_of_mut!(DMA.tx_buffers[index]) as u64;
                addr_of_mut!(DMA.tx[index]).write_volatile(TxDescriptor {
                    address: tx_address,
                    status: TX_DONE,
                    ..TxDescriptor::EMPTY
                });
            }
            nic.write(RDBAL, addr_of_mut!(DMA.rx) as u64 as u32);
            nic.write(RDBAH, 0);
            nic.write(TDBAL, addr_of_mut!(DMA.tx) as u64 as u32);
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
        function.enable_bus_master();
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
            let descriptor = unsafe { addr_of_mut!(DMA.rx[index]) };
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
                // SAFETY: length is bounded by both buffers, the static DMA
                // buffer cannot alias the caller's slice, and DD grants CPU
                // ownership until the tail write below.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        addr_of!(DMA.rx_buffers[index]).cast::<u8>(),
                        packet.as_mut_ptr(),
                        length,
                    );
                }
            }
            // SAFETY: we still own this descriptor. Clear all writeback fields
            // before the release fence and RDT return it to hardware.
            unsafe {
                descriptor.write_volatile(RxDescriptor {
                    address: addr_of_mut!(DMA.rx_buffers[index]) as u64,
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
        let status = unsafe { addr_of!(DMA.tx[self.tx_next].status).read_volatile() };
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
        // does not alias static DMA memory and its length fits BUFFER_SIZE.
        unsafe {
            let buffer = addr_of_mut!(DMA.tx_buffers[index]).cast::<u8>();
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
            addr_of_mut!(DMA.tx[index]).write_volatile(TxDescriptor {
                address: buffer as u64,
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

    fn read_mac(&self, clock: &Clock) -> Result<[u8; 6], &'static str> {
        let low = self.read(RAL).to_le_bytes();
        let high = self.read(RAH);
        let mut mac = [
            low[0],
            low[1],
            low[2],
            low[3],
            high as u8,
            (high >> 8) as u8,
        ];
        if high & (1 << 31) == 0 || !valid_mac(mac) {
            // QEMU initializes RAL/RAH, but the EEPROM fallback also handles
            // firmware that has cleared the receive-address-valid bit.
            for word in 0..3 {
                self.write(EERD, 1 | ((word as u32) << 8));
                let deadline = clock.now_millis() + 100;
                let value = loop {
                    let value = self.read(EERD);
                    if value & (1 << 4) != 0 {
                        break value;
                    }
                    if clock.now_millis() >= deadline {
                        return Err("e1000 EEPROM read timed out");
                    }
                    core::hint::spin_loop();
                };
                mac[word * 2] = (value >> 16) as u8;
                mac[word * 2 + 1] = (value >> 24) as u8;
            }
        }
        if !valid_mac(mac) {
            return Err("e1000 has no valid unicast MAC address");
        }
        Ok(mac)
    }

    fn read(&self, register: usize) -> u32 {
        // SAFETY: init validates the entire BAR within the uncached identity
        // mapping. All private callers supply aligned offsets inside the BAR.
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
