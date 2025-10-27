use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use deku::prelude::*;
use deku::{DekuRead, DekuWrite};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct SegmentTableHeader {
    magic: [u8; 4],
    flag: u32,
    table_offset: u32,
    nr_entries: u32,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct SegmentTableEntry {
    virtual_address: u32,
    /*
    -> 0xFFFFFFFF: Kernel-Space
    -> 0x00000000: User-Space
    */
    space: u32,
    file_offset: u32,
    file_size: u32,
    memory_size: u32,
    flag: u32,
    name_bytes: [u8; 8],
}

impl SegmentTableEntry {
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.name_bytes)
            .trim_matches(char::from(0))
            .to_string()
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    pub fn space(&self) -> u32 {
        self.space
    }

    pub fn file_offset(&self) -> u32 {
        self.file_offset
    }

    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    pub fn memory_size(&self) -> u32 {
        self.memory_size
    }

    pub fn flag(&self) -> u32 {
        self.flag
    }

    pub fn name_bytes(&self) -> [u8; 8] {
        self.name_bytes
    }
}

#[derive(Debug, Error)]
pub enum SegmentTableError {
    #[error("File too short")]
    FileTooShort,
    #[error("Missing header")]
    MissingHeader,
    #[error("Invalid header")]
    InvalidHeader,
    #[error("Invalid magic")]
    InvalidMagic,
    #[error("Invalid entry size")]
    InvalidEntrySize,
    #[error("Invalid entry")]  
    InvalidEntry,
}

pub fn parse(binary_view: &BinaryView) -> Result<Vec<SegmentTableEntry>, SegmentTableError> {
    /*
    The fwsg header is at the end of the file,
    with magic number 'fwsg' at offset: EOF-32,
    followed by and unknown flag, which is always 1,
    then the file offset to the start of the segment list,
    and the nr of entries.

    Each entry is 32 bytes and contains a virtual address,
    a file offset, a file size, a segment size, a flag and
    a name.
     */
    if binary_view.len() < 32 {
        return Err(SegmentTableError::FileTooShort);
    }

    let header_bytes = binary_view.read_vec(binary_view.len() - 32, 16);
    if header_bytes.len() != 16 {
        return Err(SegmentTableError::MissingHeader);
    }
    let Ok((_, header)) = SegmentTableHeader::from_bytes((header_bytes.as_slice(), 0)) else {
        return Err(SegmentTableError::InvalidHeader);
    };

    if header.magic != [b'f', b'w', b's', b'g'] {
        return Err(SegmentTableError::InvalidMagic);
    }

    let mut segments: Vec<SegmentTableEntry> = Vec::with_capacity(header.nr_entries as usize);
    let mut cursor = header.table_offset as u64;
    for _ in 0..header.nr_entries {
        let entry_bytes = binary_view.read_vec(cursor, 32);
        if entry_bytes.len() != 32 {
            return Err(SegmentTableError::InvalidEntrySize);
        }
        let Ok((_, entry)) = SegmentTableEntry::from_bytes((entry_bytes.as_slice(), 0)) else {
            return Err(SegmentTableError::InvalidEntry);
        };
        segments.push(entry);

        cursor += 32;
    }

    Ok(segments)
}
