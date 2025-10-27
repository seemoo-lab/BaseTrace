mod loader;

use crate::loader::cmd::show_sections::ShowSectionsCommand;
use crate::loader::view::SinopeBinaryView;
use binaryninja::command::register_command;
use log::debug;

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CorePluginInit() -> bool {
    // Initialize logging
    binaryninja::logger::Logger::new("C4000")
        .with_level(log::LevelFilter::Debug)
        .init();

    // Register custom architectures, workflows, demanglers,
    // function recognizers, platforms and views!
    debug!("Registering Sinope Loader");
    SinopeBinaryView::register();

    debug!("Registering Commands");
    register_command(
        "C4000\\Tools\\Show Sections",
        "Shows a list of all sections name",
        ShowSectionsCommand {},
    );

    debug!("C4000 plugin initialized");
    true
}
