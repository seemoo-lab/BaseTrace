use binaryninja::architecture::CoreArchitecture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinopeArch {
    Thumb2,
    Aarch64,
}

impl SinopeArch {
    pub fn core_arch_name(self) -> String {
        match self {
            SinopeArch::Thumb2 => "thumb2",
            SinopeArch::Aarch64 => "aarch64",
        }.to_string()
    }
}

impl Into<CoreArchitecture> for SinopeArch {
    fn into(self) -> CoreArchitecture {
        let name = self.core_arch_name();
        CoreArchitecture::by_name(name.as_str()).expect("architecture not found")
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub enum SinopeFile {
    Cdpd,
    Cdph,
    Cdpu,
    L1cs,
    Rkos,
    Data,
}

impl SinopeFile {
    pub fn from_segments(segments: Vec<String>) -> Option<SinopeFile> {
        if segments.len() == 1 && segments[0] == "__DATA" {
            return Some(SinopeFile::Data);
        }

        for segment in segments {
            match segment.as_str() {
                "__CDPDL3" => return Some(SinopeFile::Cdpd),
                "__CDPH_I" => return Some(SinopeFile::Cdph),
                "__CDPUL1" => return Some(SinopeFile::Cdpu),
                "__L1C_GN" => return Some(SinopeFile::L1cs),
                "m.APPCON" => return Some(SinopeFile::Rkos),
                _ => continue,
            }
        }
        None
    }

    pub fn architecture(self) -> SinopeArch {
        if self == SinopeFile::Cdph {
            SinopeArch::Thumb2
        } else {
            SinopeArch::Aarch64
        }
    }

    pub fn entry_point(self) -> u64 {
        match self {
            // Kernel entry point
            SinopeFile::Rkos => 0x00000800,
            // Just a guess for cdph
            SinopeFile::Cdph => 0x00100108,
            // Default user space entry point
            _ => 0x02000000,
        }
    }
}
