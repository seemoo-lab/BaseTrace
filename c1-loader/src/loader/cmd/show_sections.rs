use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;

pub struct ShowSectionsCommand {}

impl Command for ShowSectionsCommand {
    fn action(&self, view: &BinaryView) {
        let mut sections_vec = view
            .sections()
            .iter()
            .map(|s| (s.name().to_string_lossy().to_string(), s.start()))
            .collect::<Vec<(String, u64)>>();

        sections_vec.sort_by_key(|(_, start)| *start);

        let sections_str = sections_vec
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<String>>()
            .join("\n");

        view.show_plaintext_report("Sections", sections_str.as_str())
    }

    fn valid(&self, _: &BinaryView) -> bool {
        true
    }
}
