//! PCI configuration mechanism #1 for the single-CPU, polling kernel.

use core::arch::asm;

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
const COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;

#[derive(Clone, Copy)]
pub struct Function {
    bus: u8,
    device: u8,
    function: u8,
}

impl Function {
    fn config_address(self, offset: u8) -> u32 {
        (1 << 31)
            | (u32::from(self.bus) << 16)
            | (u32::from(self.device) << 11)
            | (u32::from(self.function) << 8)
            | u32::from(offset & 0xfc)
    }

    pub fn read_u32(self, offset: u8) -> u32 {
        assert!(offset.is_multiple_of(4));
        let result: u32;
        // SAFETY: we run at ring 0 with one CPU and interrupts disabled. No
        // other execution context can change CONFIG_ADDRESS between the two
        // port operations. These are the standard x86 PCI config ports.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") CONFIG_ADDRESS,
                in("eax") self.config_address(offset),
                options(nomem, nostack, preserves_flags),
            );
            asm!(
                "in eax, dx",
                in("dx") CONFIG_DATA,
                out("eax") result,
                options(nomem, nostack, preserves_flags),
            );
        }
        result
    }

    fn write_command(self, command: u16) {
        // SAFETY: the same single-CPU exclusion as read_u32 applies. A WORD
        // write changes only Command; a DWORD read/modify/write would also
        // write back the adjacent write-one-to-clear PCI Status bits.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") CONFIG_ADDRESS,
                in("eax") self.config_address(0x04),
                options(nomem, nostack, preserves_flags),
            );
            asm!(
                "out dx, ax",
                in("dx") CONFIG_DATA,
                in("ax") command,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    /// Enable MMIO, mask legacy PCI interrupts, and stop DMA during setup.
    pub fn prepare_memory(self) {
        let command = self.read_u32(0x04) as u16;
        self.write_command(
            (command | COMMAND_MEMORY | COMMAND_INTERRUPT_DISABLE) & !COMMAND_BUS_MASTER,
        );
    }

    pub fn enable_bus_master(self) {
        let command = self.read_u32(0x04) as u16;
        self.write_command(
            command | COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_INTERRUPT_DISABLE,
        );
    }
}

/// Search every bus, including buses configured behind firmware PCI bridges.
/// Nonexistent devices return vendor 0xffff; extra functions are probed only
/// when function zero advertises a multifunction device.
pub fn find(vendor: u16, device_id: u16) -> Option<Function> {
    let identity = (u32::from(device_id) << 16) | u32::from(vendor);
    for bus in 0..=u8::MAX {
        for device in 0..32 {
            let first = Function {
                bus,
                device,
                function: 0,
            };
            let first_id = first.read_u32(0);
            if first_id as u16 == 0xffff {
                continue;
            }
            if first_id == identity {
                return Some(first);
            }
            if first.read_u32(0x0c) & (1 << 23) == 0 {
                continue;
            }
            for function in 1..8 {
                let candidate = Function { function, ..first };
                if candidate.read_u32(0) == identity {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
