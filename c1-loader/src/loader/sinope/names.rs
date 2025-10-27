use crate::loader::sinope::file::SinopeFile;
use crate::loader::sinope::segment::SinopeSpace;
use log::warn;
use std::collections::HashMap;

type SegmentLookupMap = HashMap<&'static str, Vec<&'static str>>;

pub struct SegmentNameLookup {
    // for rkos: 6 chars -> vec![name]
    // for others: 8 chars -> vec![name]
    lookup: HashMap<SinopeFile, SegmentLookupMap>,
}

impl SegmentNameLookup {
    // rkos with prefix "m." & "r."
    const RKOS: [&'static str; 71] = [
        // In all binaries, the __DATA__CONST segment always follows the __DATA segment.
        // Thus, we assume a similar pattern for rkos.
        "__DATA",
        "__DATA_CONST",
        "APPCONFIG",
        "__PW_DVFM_SEG",
        "__PW_PERF_SEG",
        "__MHOST_RNG_SEG",
        "__RF_INIT_SEG",
        "__IOSM_CSHM_SEG",
        "__GTI_SHM_SEG",
        "__CPS_DP_SEG",
        "__CPS_FPDB_SEG",
        "__EXPRO_SEG",
        "__SYS_DASH_SEG",
        "__RT_SENSOR_SEG",
        "__SENSOR_SEG",
        "__SAH_CPS_SEG",
        "__MX_DL_CPS_SEG",
        "__MX_UL_CPS_SEG",
        "__ICC_POOL_SEG",
        "__UE_CAP_SEG",
        "__RO_DATA_SEG",
        "__DRAM_NC_SEG",
        "__DRAM_SHM_SEG",
        "__CPS_ICC_SEG",
        "__SHMS_NVM_SEG",
        "__SHMC_NVM_SEG",
        "__SHMP_NVM_SEG",
        "__SHMD_NVM_SEG",
        "__PBM_SHM_SEG",
        "__CMM_SEG",
        "__NVM_C_SEG",
        "__NVMS_SEG",
        "__NVM_F_SEG",
        "__NVM_D_SEG",
        "__MSG_CPS_SEG",
        "__MSG2_CPS_SEG",
        "__PS_FW_DB_SEG",
        "__L1MEM_TRC_SEG",
        "__TAGGR_MEM_SEG",
        "__CPS_SCV_SEG",
        "__MC_SHM_SEG",
        "__ICC_PLSW_SEG",
        "_MW_ICC_SEG",
        "__OTA_ICC_SEG",
        "__MFWK_PLSW_SEG",
        "__MW_MFWK_SEG",
        "__OTA_MFWK_SEG",
        "__2G_DATA_SEG",
        "__2G_CODE_SEG",
        "__CMSG_PLSW_SEG",
        "__MW_CMSG_SEG",
        "__OTA_CMSG_SEG",
        "__DMA_OTA_SEG",
        "__RO_NVM_SEG",
        "__MW_OTA_SEG",
        "__L2DPU_SEG",
        "__NC_L2DPU_SEG",
        "__RW_RO_RO_CPS",
        "__RW_CPS",
        "__PDE_TEST",
        "__RO_C_RFNVM_SEG",
        "__RO_S_RFNVM_SEG",
        "__SHM_NVM_SEG",
        "__3G_DATA_SEG",
        "__3G_CODE_SEG",
        "__OVERLAY_SEG",
        "__OPBM_SHM_SEG",
        "__SRAM_TEXT_SEG",
        "__CPSICC_S_SEG",
        "__SRAM_SEG",
        "__NC_SRAM_SEG",
    ];

    const L1CS: [&'static str; 63] = [
        "__TEXT",
        "__DATA",
        "__DATA_CONST",
        // l1cf
        "__L1C_DP_SEG",
        "__MSG_L1C2_SEG",
        "__MSG2_L1C_SEG",
        "__RTM_IQ_SEG",
        "__RF_FR1_SEG",
        "__RF_FR2_SEG",
        "__DRAM_NC_SEG",
        "__L1C_4_SEG",
        "__L1C_ICC_SEG",
        "__L1C_CPS_SEG",
        "__L1C_IPC_SEG",
        "__L1C_GNSS_SEG",
        "__GNSS_FW_SEG",
        "__FW3G_SEG",
        "__L1C_3_SEG",
        "__L1C_1_SEG",
        "__STW_PCM_SEG",
        "__L1C_2_SEG",
        "__OL1C_ICC_SEG",
        "__ML1C_ICC_SEG",
        "__CMM_SEG",
        // cdph
        "__MSG_CHOST_SEG",
        // cdpd
        "__MSG_DL_SEG",
        // cdpu
        "__MSG_UL_SEG",
        "__CDPDLICC_SEG",
        "__CDPULICC_SEG",
        "__CDPH_ICC_SEG",
        // cps
        "__SHMS_NVM_SEG",
        "__SHMC_NVM_SEG",
        "__MSG2_UL_SEG",
        "__CDPDL3_SEG",
        "__MSG2_CH_SEG",
        "__CPS_DP_SEG",
        "__ICC_POOL_SEG",
        "__RO_DATA_SEG",
        "__MSG_CPS_SEG",
        "__SAH_CPS_SEG",
        "__SENSOR_SEG",
        "__RT_SENSOR_SEG",
        "__CPS_ICC_SEG",
        "__EXPRO_SEG",
        "__CPS_FPDB_SEG",
        "__GTI_SHM_SEG",
        "__PW_PERF_SEG",
        "__PW_DVFM_SEG",
        "__PBM_SHM_SEG",
        "__MSG2_CPS_SEG",
        "__PS_FW_DB_SEG",
        "__L1MEM_TRC_SEG",
        "__TAGGR_MEM_SEG",
        "__DRAM_SHM_SEG",
        "__CPMS_SHM_SEG",
        "__CMSG_PLSW_SEG",
        "__RW_CPS",
        "__PDE_TEST",
        "__RO_NVM_SEG",
        "__DLICC_S_SEG",
        "__CHICC_S_SEG",
        "__ULICC_S_SEG",
        "__CPSICC_S_SEG",
    ];

    const CDPD: [&'static str; 63] = [
        "__TEXT",
        "__DATA",
        "__DATA_CONST",
        // cdpd
        "__MSG_DL_SEG",
        "__CDPDL3_SEG",
        "__L2_RLC_SEG",
        "__L2_PDCP_SEG",
        "__PDCPSN_SEG",
        "__CDPDL1_SEG",
        "__CDPDL2_SEG",
        "__DL_PDCP_SEG",
        "__L3DL_PTM_SEG",
        "__GDCI_SEG",
        "__RSM_SEG",
        "__DRAM_NC_SEG",
        "__CDPDLICC_SEG",
        "__PCM_IPC_SEG",
        "__OCDPDLICC_SEG",
        "__MCDPDLICC_SEG",
        "__CMM_SEG",
        "__GDCISRAM_SEG",
        "__SRAM_L23DL_SEG",
        "__GDUCSRAM_SEG",
        "__SRAM_RLC_SEG",
        "__DLICC_S_SEG",
        "__SRAM_SEG",
        // cdpu
        "__UL_RSM_SEG",
        "__CDPUL1_SEG",
        "__CDPULICC_SEG",
        // l1cf
        "__L1C_ICC_SEG",
        // cdph
        "__CDPH_ICC_SEG",
        "__L1C_IPC_SEG",
        "__L2UL_L2PB_SEG",
        "__MSG2_UL_SEG",
        "__MSG2_L1C_SEG",
        "__MSG2_CH_SEG",
        "__DRAMUPTM_SEG",
        // cps
        "__RW_CPS",
        "__DRAM_PCM_SEG",
        "__MSG_CPS_SEG",
        "__SAH_CPS_SEG",
        "__SENSOR_SEG",
        "__RT_SENSOR_SEG",
        "__PBM_SHM_SEG",
        "__CPS_ICC_SEG",
        "__EXPRO_SEG",
        "__PW_PERF_SEG",
        "__PW_DVFM_SEG",
        "__MSG2_CPS_SEG",
        "__MX_DL_CPS_SEG",
        "__DRAM_SHM_SEG",
        "__MX_UL_DL_SEG",
        "__MSG_CHOST_SEG",
        "__MSG_L1C2_SEG",
        "__MSG_UL_SEG",
        "__PDE_TEST",
        "__MW_MFWK_SEG",
        "__SRAM_CH_SEG",
        "__SRAM_PCM_SEG",
        "__CHICC_S_SEG",
        "__ULICC_S_SEG",
        "__CPSICC_S_SEG",
        "__ULPCM_S_SEG",
    ];

    const CDPH: [&'static str; 66] = [
        "__TEXT",
        "__DATA",
        "__SRAM_TEXT_SEG",
        "__SRAM_SEG",
        "__SRAM_NC_SEG",
        "__CHICC_S_SEG",
        "__SRAM_PCM_SEG",
        "__SRAM_CH_SEG",
        "__DRAM_T_SEG",
        "__DRAM_D_SEG",
        "__DRAM_NC_SEG",
        "__L3UL_DRB_SEG",
        "__DRAM_SHM_SEG",
        "__MSG_CHOST_SEG",
        "__MSG_CPS_SEG",
        "__MSG_L1C2_SEG",
        "__MSG_DL_SEG",
        "__MSG_UL_SEG",
        "__MSG2_CH_SEG",
        "__MSG2_L1C_SEG",
        "__CDPDL3_SEG",
        "__MSG2_UL_SEG",
        "__MSG2_CPS_SEG",
        "__SAH_CPS_SEG",
        "__DRAM_PCM_SEG",
        "__L2_PDCP_SEG",
        "__PDCPSN_SEG",
        "__L3DL_PTM_SEG",
        "__RSM_SEG",
        "__SRAM_L23DL_SEG",
        "__GDCISRAM_SEG",
        "__GDUCSRAM_SEG",
        "__DLICC_S_SEG",
        "__SRAM_L2FE_SEG",
        "__SRAMUPTM_SEG",
        "__SRAMUGDCI_SEG",
        "__DRAM_L2FE_SEG",
        "__DRAMUPTM_SEG",
        "__DRAMUGDCI_SEG",
        "__UL_RSM_SEG",
        "__CDPUL1_SEG",
        "__CDPH_1_SEG",
        "__SENSOR_SEG",
        "__RT_SENSOR_SEG",
        "__PBM_SHM_SEG",
        "__CPS_ICC_SEG",
        "__CDPDLICC_SEG",
        "__L2UL_L2PB_SEG",
        "__CDPULICC_SEG",
        "__L1C_ICC_SEG",
        "__CDPH_ICC_SEG",
        "__EXPRO_SEG",
        "__L1C_IPC_SEG",
        "__IOSM_CSHM_SEG",
        "__MHOST_RNG_SEG",
        "__DL_PDCP_SEG",
        "__PW_PERF_SEG",
        "__CPSICC_S_SEG",
        "__ULICC_S_SEG",
        "__PCM_IPC_SEG",
        "__PCMUL_IPC_SEG",
        "__ULPCM_S_SEG",
        "__OCDPH_ICC_SEG",
        "__PCDPH_ICC_SEG",
        "__MCDPH_ICC_SEG",
        "__PDE_TEST",
    ];

    const CDPU: [&'static str; 67] = [
        "__TEXT",
        "__DATA",
        "__DATA_CONST",
        // cdpu
        "__MX_UL_DL_SEG",
        "__MSG_UL_SEG",
        "__MSG2_UL_SEG",
        "__DRAM_L2FE_SEG",
        "__DRAM_FEUC_SEG",
        "__DRAMUPTM_SEG",
        "__DRAMUGDCI_SEG",
        "__UL_RSM_SEG",
        "__CDPUL1_SEG",
        "__DRAM_NC_SEG",
        "__L2UL_L2PB_SEG",
        "__CDPULICC_SEG",
        "__PCMUL_IPC_SEG",
        "__CPMS_SHM_SEG",
        "__OCDPULICC_SEG",
        "__MCDPULICC_SEG",
        "__CMM_SEG",
        "__ULPCM_S_SEG",
        "__ULICC_S_SEG",
        "__SRAM_L2FE_SEG",
        "__SRAMUPTM_SEG",
        "__SRAMUGDCI_SEG",
        // cdpd
        "__L2_RLC_SEG",
        "__DL_PDCP_SEG",
        "__L3DL_PTM_SEG",
        "__CDPDLICC_SEG",
        // l1cf
        "__L1C_ICC_SEG",
        // cdph
        "__CDPH_ICC_SEG",
        "__L1C_IPC_SEG",
        "__PDCPSN_SEG",
        "__CDPDL2_SEG",
        "__L3UL_DRB_SEG",
        "__CDPDL3_SEG",
        "__MSG2_L1C_SEG",
        "__MSG2_CH_SEG",
        "__MSG_CHOST_SEG",
        "__MSG_L1C2_SEG",
        "__MSG_DL_SEG",
        "__DRAM_PCM_SEG",
        "__MSG_CPS_SEG",
        "__SAH_CPS_SEG",
        "__SENSOR_SEG",
        "__RT_SENSOR_SEG",
        "__PBM_SHM_SEG",
        "__CPS_ICC_SEG",
        "__EXPRO_SEG",
        "__PW_PERF_SEG",
        "__PW_DVFM_SEG",
        "__MSG2_CPS_SEG",
        "__MX_UL_CPS_SEG",
        "__DRAM_SHM_SEG",
        "__PCM_IPC_SEG",
        "__RW_CPS",
        "__L2_PDCP_SEG",
        "__PDE_TEST",
        "__STW_PCM_SEG",
        "__MW_MFWK_SEG",
        "__SRAM_L23DL_SEG",
        "__GDUCSRAM_SEG",
        "__SRAM_CH_SEG",
        "__SRAM_PCM_SEG",
        "__DLICC_S_SEG",
        "__CHICC_S_SEG",
        "__CPSICC_S_SEG",
    ];

    pub fn new() -> SegmentNameLookup {
        let mut lookup: HashMap<SinopeFile, SegmentLookupMap> = HashMap::new();
        lookup.insert(SinopeFile::Cdpd, Self::new_lookup(8, &Self::CDPD));
        lookup.insert(SinopeFile::Cdph, Self::new_lookup(8, &Self::CDPH));
        lookup.insert(SinopeFile::Cdpu, Self::new_lookup(8, &Self::CDPU));
        lookup.insert(SinopeFile::L1cs, Self::new_lookup(8, &Self::L1CS));
        lookup.insert(SinopeFile::Rkos, Self::new_lookup(6, &Self::RKOS));
        SegmentNameLookup { lookup }
    }

    fn new_lookup<'a>(
        chars: usize,
        names: &'static [&str],
    ) -> HashMap<&'static str, Vec<&'static str>> {
        let mut map = HashMap::new();
        for name in names {
            let len = if chars > name.len() {name.len()} else { chars };
            if let Some(name_start) = name.get(..len) {
                map.entry(name_start).or_insert_with(Vec::new).push(*name);
            }  else {
                warn!("Unable to get short name for segment name: {}", name)
            }
        }
        map
    }

    pub fn expand(
        &self,
        file: SinopeFile,
        name: &str,
        space: SinopeSpace,
        part: Option<u32>,
    ) -> String {
        let Some(lookup_map) = &self.lookup.get(&file) else {
            warn!("No segment name lookup map for {:?}", file);
            return name.to_string();
        };

        let part_id = part.unwrap_or(0) as usize;
        let part_suffix = if let Some(part) = part {
            format!("_P{}", part)
        } else {
            "".to_string()
        };
        let default_name = format!("{}{}", name, part_suffix);

        // Append KERNEL prefix to kernel segments
        if space == SinopeSpace::Kernel {
            return format!("KERNEL{}", default_name);
        }

        // Keep names as is for segments whose name is shorter than 8 characters
        if name.len() < 8 {
            return default_name;
        }

        // Perform special handling for Rkos segments with are effectively 6 characters long
        if file == SinopeFile::Rkos && name.chars().nth(1).unwrap_or('0') == '.' {
            // we only process names starting with "r" or "m"
            if !name.starts_with("r") && !name.starts_with("m") {
                return default_name;
            }

            // split the name into the components of space and short name
            let space = &name[..1];
            let short_name = &name[2..];

            // get all applicable expanded names for this short name
            let Some(expanded_names) = &lookup_map.get(short_name) else {
                return default_name;
            };
            // select the name by part number
            let Some(expanded_name) = expanded_names.get(part_id) else {
                return default_name;
            };
            // we don't require a path suffix
            format!("{}.{}", space, expanded_name)
        } else {
            let Some(expanded_names) = lookup_map.get(name) else {
                return default_name;
            };
            // select the name by part number
            let Some(expanded_name) = expanded_names.get(part_id) else {
                return default_name;
            };
            // we don't require a path suffix
            expanded_name.to_string()
        }
    }
}
