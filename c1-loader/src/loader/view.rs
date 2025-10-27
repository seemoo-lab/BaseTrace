use crate::loader::fwsg;
use crate::loader::fwsg::{SegmentTableEntry, SegmentTableError};
use crate::loader::sinope::file::SinopeFile;
use crate::loader::sinope::names::SegmentNameLookup;
use crate::loader::sinope::segment::{SinopeSegment, SinopeSegmentFlag};
use binaryninja::Endianness;
use binaryninja::architecture::{Architecture, ArchitectureExt, CoreArchitecture};
use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::custom_binary_view::{
    BinaryViewType, BinaryViewTypeBase, CustomBinaryView, CustomBinaryViewType, CustomView,
    CustomViewBuilder, register_view_type,
};
use binaryninja::section::{SectionBuilder, Semantics};
use binaryninja::segment::{SegmentBuilder, SegmentFlags};
use log::{debug, info, warn};
use thiserror::Error;

type BinaryViewResult<R> = binaryninja::binary_view::Result<R>;

pub const VIEW_TYPE_NAME: &str = "Apple Sinope Loader";
pub const VIEW_TYPE_LONG_NAME: &str = "Apple Sinope Loader (C4000)";

#[derive(Debug, Error)]
enum SinopeBinaryViewError {
    #[error("Invalid parent binary view")]
    InvalidParentBinaryView,
    #[error("Unknown file type")]
    UnknownFile,
    #[error("Invalid segment table {0}")]
    InvalidSegmentTable(SegmentTableError),
}

pub struct SinopeBinaryViewType {
    view_type: BinaryViewType,
}

impl SinopeBinaryViewType {
    pub fn new(view_type: BinaryViewType) -> Self {
        Self { view_type }
    }
}

impl AsRef<BinaryViewType> for SinopeBinaryViewType {
    fn as_ref(&self) -> &BinaryViewType {
        &self.view_type
    }
}

impl BinaryViewTypeBase for SinopeBinaryViewType {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        let res = SinopeBinaryView::file_from_view(&data);
        debug!("Is SinopeBinaryViewType applicable for view? {:?}", res);
        res.is_ok()
    }
}

impl CustomBinaryViewType for SinopeBinaryViewType {
    fn create_custom_view<'builder>(
        &self,
        data: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> binaryninja::binary_view::Result<CustomView<'builder>> {
        debug!("Creating Sinope Binary View from View Type");
        let binary_view = builder.create::<SinopeBinaryView>(data, ());
        binary_view
    }
}

pub struct SinopeBinaryView {
    inner: binaryninja::rc::Ref<BinaryView>,
    file: Option<SinopeFile>,
    name_lookup: SegmentNameLookup,
}

impl SinopeBinaryView {
    pub fn new(view: &BinaryView) -> Self {
        debug!("New SinopeBinaryView");
        Self {
            inner: view.to_owned(),
            file: None,
            name_lookup: SegmentNameLookup::new(),
        }
    }

    fn init_internal(&mut self) -> Result<(), SinopeBinaryViewError> {
        debug!("SinopeBinaryView init_internal");

        let Some(parent_view) = self.parent_view() else {
            warn!("No parent view");
            return Err(SinopeBinaryViewError::InvalidParentBinaryView);
        };

        let (c1_file, entries) = SinopeBinaryView::file_from_view(&parent_view)?;
        self.file = Some(c1_file);

        // Convert entries to segments
        let segments = SinopeSegment::new_vec(&entries, c1_file, &self.name_lookup);

        debug!("C1 File Type: {:?}", c1_file);
        debug!("Architecture: {:?}", c1_file.architecture());
        debug!("Segments:");
        segments.iter().for_each(|s| info!("{:?}", s));

        let arch: CoreArchitecture = c1_file.architecture().into();
        let platform = arch.standalone_platform().expect("platform not found");

        self.set_default_arch(&arch);
        self.set_default_platform(&platform);

        for segment in segments {
            debug!("Loading segment: {:?}", segment.expand_name());
            let flags = if segment.flag() == SinopeSegmentFlag::Executable {
                SegmentFlags::new()
                    .readable(true)
                    .executable(true)
                    .contains_code(true)
                    .deny_write(true)
            } else {
                SegmentFlags::new()
                    .readable(true)
                    .writable(true)
                    .deny_write(true)
            };

            let builder = SegmentBuilder::new(segment.virtual_range())
                .parent_backing(segment.file_range())
                .flags(flags)
                .is_auto(true);
            self.add_segment(builder);

            let semantics = if segment.flag() == SinopeSegmentFlag::Executable {
                Semantics::ReadOnlyCode
            } else {
                Semantics::ReadWriteData
            };

            let section =
                SectionBuilder::new(segment.expand_name().to_string(), segment.virtual_range())
                    .is_auto(true)
                    .semantics(semantics);
            self.add_section(section);
        }

        Ok(())
    }

    fn file_from_view(
        binary_view: &BinaryView,
    ) -> Result<(SinopeFile, Vec<SegmentTableEntry>), SinopeBinaryViewError> {
        // Load all segment table entries from the parent view
        let entries =
            fwsg::parse(&binary_view).map_err(SinopeBinaryViewError::InvalidSegmentTable)?;

        // Determine the C1 file type based on the segment names
        let segment_names: Vec<String> = entries.iter().map(|s| s.name().to_string()).collect();
        debug!("Found segment names: {:?}", segment_names);
        let Some(file) = SinopeFile::from_segments(segment_names) else {
            return Err(SinopeBinaryViewError::UnknownFile);
        };

        Ok((file, entries))
    }

    pub fn register() {
        register_view_type(
            VIEW_TYPE_NAME,
            VIEW_TYPE_LONG_NAME,
            SinopeBinaryViewType::new,
        );
    }
}

impl AsRef<BinaryView> for SinopeBinaryView {
    fn as_ref(&self) -> &BinaryView {
        &self.inner
    }
}

impl BinaryViewBase for SinopeBinaryView {
    fn executable(&self) -> bool {
        true
    }

    fn relocatable(&self) -> bool {
        true
    }

    fn entry_point(&self) -> u64 {
        if let Some(file) = self.file {
            file.entry_point()
        } else {
            0x02000000
        }
    }

    fn default_endianness(&self) -> Endianness {
        // Default for ARM
        Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        if let Some(file) = self.file {
            let arch: CoreArchitecture = file.architecture().into();
            arch.address_size()
        } else {
            info!("No architecture set, assuming 64-bit address space");
            64
        }
    }
}

unsafe impl CustomBinaryView for SinopeBinaryView {
    type Args = ();

    fn new(handle: &BinaryView, _: &Self::Args) -> binaryninja::binary_view::Result<Self> {
        Ok(SinopeBinaryView::new(handle))
    }

    fn init(&mut self, _: Self::Args) -> BinaryViewResult<()> {
        match self.init_internal() {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Failed to init SinopeBinaryView: {:?}", err);
                Err(())
            }
        }
    }
}
