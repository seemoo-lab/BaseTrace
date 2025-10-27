use crate::loader::fwsg::SegmentTableEntry;
use crate::loader::sinope::file::SinopeFile;
use crate::loader::sinope::names::SegmentNameLookup;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Range;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SinopeSpace {
    User,
    Kernel,
    Unknown(u32),
}

impl From<u32> for SinopeSpace {
    fn from(value: u32) -> Self {
        match value {
            0xFFFFFFFF => SinopeSpace::Kernel,
            0x00000000 => SinopeSpace::User,
            _ => SinopeSpace::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SinopeSegmentFlag {
    Data,
    Executable,
    Unknown(u32),
}

impl From<u32> for SinopeSegmentFlag {
    fn from(value: u32) -> Self {
        match value {
            0x0 => SinopeSegmentFlag::Data,
            0x4 => SinopeSegmentFlag::Executable,
            _ => SinopeSegmentFlag::Unknown(value),
        }
    }
}

#[derive(Clone)]
pub struct SinopeSegment {
    virtual_address: u32,
    space: SinopeSpace,
    file_offset: u32,
    file_size: u32,
    memory_size: u32,
    flag: SinopeSegmentFlag,
    name: String,
    expanded_name: String,
    part: Option<u32>,
}

impl SinopeSegment {
    pub fn new_vec(
        entries: &Vec<SegmentTableEntry>,
        file: SinopeFile,
        names: &SegmentNameLookup,
    ) -> Vec<SinopeSegment> {
        // Count the number of times each short segment name appears.
        // There may be duplicates.
        let mut name_counter: HashMap<String, u32> = HashMap::new();
        let mut entry_part: Vec<(&SegmentTableEntry, u32)> = Vec::with_capacity(entries.len());
        for entry in entries {
            let count = name_counter.entry(entry.name()).or_insert(0);
            entry_part.push((entry, *count));
            *count += 1;
        }

        // Assign each segment a part number if its name appears more than once.
        // If not, the part is None
        let mut segments = Vec::with_capacity(entries.len());
        for (entry, part) in entry_part {
            let name_count = *name_counter.get(&entry.name()).unwrap_or(&1);
            segments.push(Self::new(
                entry,
                file.clone(),
                if name_count == 1 { None } else { Some(part) },
                names,
            ));
        }

        segments
    }

    fn new(
        entry: &SegmentTableEntry,
        file: SinopeFile,
        part: Option<u32>,
        names: &SegmentNameLookup,
    ) -> Self {
        let space: SinopeSpace = entry.space().into();
        let name = entry.name();

        Self {
            virtual_address: entry.virtual_address(),
            space,
            file_offset: entry.file_offset(),
            file_size: entry.file_size(),
            memory_size: entry.memory_size(),
            flag: entry.flag().into(),
            name: name.clone(),
            expanded_name: names.expand(file, name.as_str(), space, part),
            part,
        }
    }

    pub fn virtual_range(&self) -> Range<u64> {
        self.virtual_address as u64..(self.virtual_address + self.memory_size) as u64
    }

    pub fn file_range(&self) -> Range<u64> {
        self.file_offset as u64..(self.file_offset + self.file_size) as u64
    }

    pub fn flag(&self) -> SinopeSegmentFlag {
        self.flag
    }

    pub fn expand_name(&self) -> &str {
        self.expanded_name.as_str()
    }
}

impl Debug for SinopeSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug modifiers do not respect the width parameter,
        // so we first have to convert them to strings.
        let flag_str = format!("{:?}", self.flag);
        let space_str = format!("{:?}", self.space);
        let part_str = self
            .part
            .map(|x| x.to_string())
            .unwrap_or("None".to_string());

        // https://doc.rust-lang.org/std/fmt/index.html
        write!(
            f,
            "{:#010x}-{:#010x}({:#010x}) f:{:#010x}-{:#010x}({:#010x}) flags={:10} space={:6} part={:4} {:8} -> {}",
            self.virtual_address,
            self.virtual_address + self.memory_size,
            self.memory_size,
            self.file_offset,
            self.file_offset + self.file_size,
            self.file_size,
            flag_str,
            space_str,
            part_str,
            self.name,
            self.expanded_name
        )
    }
}
