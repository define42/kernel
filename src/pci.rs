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
    identity: u32,
}

impl Function {
    #[cfg(not(feature = "userspace-test"))]
    pub fn bus(self) -> u8 {
        self.bus
    }

    #[cfg(not(feature = "userspace-test"))]
    pub fn device(self) -> u8 {
        self.device
    }

    #[cfg(not(feature = "userspace-test"))]
    pub fn function(self) -> u8 {
        self.function
    }

    /// Vendor/device identity captured by the scanner; these do not perform I/O.
    #[cfg(not(feature = "userspace-test"))]
    pub fn vendor_id(self) -> u16 {
        self.identity as u16
    }

    #[cfg(not(feature = "userspace-test"))]
    pub fn device_id(self) -> u16 {
        (self.identity >> 16) as u16
    }

    /// Base class, subclass and programming interface packed as 0xBBSSPP.
    /// Performs one configuration DWORD read and does not alter the device.
    #[cfg(not(feature = "userspace-test"))]
    pub fn class_code(self) -> u32 {
        self.read_u32(0x08) >> 8
    }

    #[cfg(not(feature = "userspace-test"))]
    pub fn devfn(self) -> u8 {
        (self.device << 3) | self.function
    }

    #[cfg(not(feature = "userspace-test"))]
    pub fn disable_bus_master(self) {
        let command = self.read_u32(0x04) as u16;
        self.write_command((command | COMMAND_INTERRUPT_DISABLE) & !COMMAND_BUS_MASTER);
    }

    #[cfg(not(feature = "userspace-test"))]
    pub fn bus_master_enabled(self) -> bool {
        self.read_u32(0x04) & u32::from(COMMAND_BUS_MASTER) != 0
    }

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

/// Incremental enumeration of every firmware-configured PCI bus.
///
/// Each `next_probe` step performs at most one configuration DWORD read. The
/// address-port selection is the only write; scanning never changes a device's
/// configuration, sizes a BAR, or enables a bridge/device. This bounds work for
/// callers that must keep scheduling other services while inspecting the bus.
/// Mechanism #1 covers PCI segment zero only; bridge numbering is not changed.
pub struct Scanner {
    // Packed bus/device/function cursor, with 0x10000 as the finished sentinel.
    next: u32,
    header: bool,
}

impl Scanner {
    pub const fn new() -> Self {
        Self {
            next: 0,
            header: false,
        }
    }

    /// `None`: finished, with no I/O. `Some(None)`: exactly one probe completed
    /// without yielding a function (absent vendor or function-zero header).
    /// `Some(Some(function))`: exactly one identity read found a function.
    ///
    /// Extra functions are examined only after a present function zero reports
    /// the multifunction header bit. Inspecting that bit is its own bounded
    /// step, so even finding a populated slot costs only one read in this call.
    pub fn next_probe(&mut self) -> Option<Option<Function>> {
        let function = self.current()?;
        let value = function.read_u32(if self.header { 0x0c } else { 0 });
        Some(self.complete_probe(value))
    }

    fn current(&self) -> Option<Function> {
        if self.next >= 0x1_0000 {
            return None;
        }
        Some(Function {
            bus: (self.next >> 8) as u8,
            device: ((self.next >> 3) & 31) as u8,
            function: (self.next & 7) as u8,
            identity: 0,
        })
    }

    // Cursor advancement has no port I/O, allowing exhaustive host validation
    // of termination and multifunction handling without emulating hardware.
    fn complete_probe(&mut self, value: u32) -> Option<Function> {
        if self.header {
            self.header = false;
            self.next += if value & (1 << 23) != 0 { 1 } else { 8 };
            return None;
        }
        let mut function = self.current()?;
        let present = value as u16 != 0xffff;
        if function.function == 0 && present {
            self.header = true;
        } else {
            self.next += if function.function == 0 { 8 } else { 1 };
        }
        if present {
            function.identity = value;
            Some(function)
        } else {
            None
        }
    }
}

/// Search every bus, including buses configured behind firmware PCI bridges.
/// Discovery and interactive inspection use the same enumeration policy.
#[cfg(feature = "userspace-test")]
pub fn find(vendor: u16, device_id: u16) -> Option<Function> {
    let identity = (u32::from(device_id) << 16) | u32::from(vendor);
    let mut scanner = Scanner::new();
    while let Some(probe) = scanner.next_probe() {
        if let Some(function) = probe
            && function.identity == identity
        {
            return Some(function);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::Scanner;

    #[test]
    fn absent_slots_skip_extra_functions_and_terminate_after_all_buses() {
        let mut scanner = Scanner::new();
        let mut slots = 0;
        while let Some(function) = scanner.current() {
            assert_eq!(function.function, 0);
            assert!(!scanner.header);
            assert!(scanner.complete_probe(u32::MAX).is_none());
            slots += 1;
        }
        assert_eq!(slots, 256 * 32);
        assert_eq!(scanner.next, 0x1_0000);
        // Finished calls must remain finished without touching privileged I/O.
        assert!(scanner.next_probe().is_none());
        assert!(scanner.next_probe().is_none());
    }

    #[test]
    fn single_function_header_skips_only_its_own_extra_functions() {
        let mut scanner = Scanner::new();
        let function = scanner.complete_probe(0x5678_1234).unwrap();
        assert_eq!(function.identity, 0x5678_1234);
        assert_eq!(
            (function.bus, function.device, function.function),
            (0, 0, 0)
        );
        assert!(scanner.header);
        assert_eq!(scanner.next, 0);
        assert!(scanner.complete_probe(0).is_none());
        let next = scanner.current().unwrap();
        assert_eq!((next.bus, next.device, next.function), (0, 1, 0));
    }

    #[test]
    fn all_multifunction_slots_visit_every_bdf_once_including_last_function() {
        let mut scanner = Scanner::new();
        let mut found = 0;
        let mut probes = 0;
        while scanner.current().is_some() {
            let value = if scanner.header { 1 << 23 } else { 0x5678_1234 };
            if let Some(function) = scanner.complete_probe(value) {
                let bdf = (u32::from(function.bus) << 8)
                    | (u32::from(function.device) << 3)
                    | u32::from(function.function);
                assert_eq!(bdf, found);
                found += 1;
            }
            probes += 1;
        }
        assert_eq!(found, 256 * 32 * 8);
        assert_eq!(probes, 256 * 32 * 9);
        assert_eq!(scanner.next, 0x1_0000);
    }
}
