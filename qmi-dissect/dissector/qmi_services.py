from qmi_structures import QMIService

# The service list is extracted from libqmi & iPhone firmware.
# If possible, we choose to use the iPhone's naming conventions,
# but fall back if libqmi has to offer additional service data.
# Sources:
# - libATCommandStudioDynamic.dylib!qmi::asShortString
# - libATCommandStudioDynamic.dylib!qmi::asLongString
# - https://gitlab.freedesktop.org/mobile-broadband/libqmi/-/blob/main/src/libqmi-glib/qmi-enums.h
# - https://gitlab.freedesktop.org/mobile-broadband/libqmi/-/tree/main/data
iphone_services: list[QMIService] = [
    QMIService(0x00, "ctl", "Control Service"),
    QMIService(0x01, "wds", "Wireless Data Service"),
    QMIService(0x02, "dms", "Device Management Service"),
    QMIService(0x03, "nas", "Network Access Service"),
    QMIService(0x04, "qos", "QoS Service"),
    QMIService(0x05, "wms", "Wireless Messaging Service"),
    QMIService(0x06, "pds", "Position Determination Service"),

    # iPhone: not listed
    QMIService(0x07, "auth", "Authentication service"),

    QMIService(0x08, "at", "Access Terminal Service"),
    # libqmi: 'voice' -> We use the iPhone's name to support the extracted definitions
    QMIService(0x09, "vs", "Voice Service", "voice"),
    # libqmi: 'cat2' -> We use the iPhone's name to support the extracted definitions,
    #                   although cat is defined later by libqmi
    QMIService(0x0A, "cat", "Card App Toolkit", "cat2"),
    QMIService(0x0B, "uim", "User Identity Module"),
    QMIService(0x0C, "pbm", "Phonebook Manager Service"),

    # iPhone: not listed
    QMIService(0x0D, "qchat", "QCHAT Service"),
    # iPhone: not listed
    QMIService(0x0E, "rmtfs", "Remote File System Service"),
    # iPhone: not listed
    QMIService(0x0F, "test", "Test Service"),
    # iPhone: not listed
    QMIService(0x10, "loc", "Location Service"),
    # iPhone: not listed
    QMIService(0x11, "sar", "Specific Absorption Rate"),
    # iPhone: not listed
    QMIService(0x12, "ims", "IMS Settings Service"),
    # iPhone: not listed
    QMIService(0x13, "adc", "Analog to Digital Converter Driver Service"),
    # iPhone: not listed
    QMIService(0x14, "csd", "Core Sound Driver Service"),
    # iPhone: not listed
    QMIService(0x15, "mfs", "Modem Embedded File System Service"),
    # iPhone: not listed
    QMIService(0x16, "time", "Time Service"),
    # iPhone: not listed
    QMIService(0x17, "ts", "Thermal Sensors Service"),
    # iPhone: not listed
    QMIService(0x18, "tmd", "Thermal Mitigation Device Service"),
    # iPhone: not listed
    QMIService(0x19, "sap", "Service Access Proxy Service"),

    QMIService(0x1A, "wda", "Wireless Data Administrative Service"),

    # iPhone: not listed
    QMIService(0x1B, "tsync", "TSYNC Control Service"),
    # iPhone: not listed
    QMIService(0x1C, "rfsa", "Remote File System Access Service"),
    # iPhone: not listed
    QMIService(0x1D, "csvt", "Circuit Switched Videotelephony Service"),
    # iPhone: not listed
    QMIService(0x1E, "qcmap", "Qualcomm Mobile Access Point Service"),
    # IMS = IP Multimedia Subsystem (https://en.wikipedia.org/wiki/IP_Multimedia_Subsystem)
    # iPhone: not listed
    QMIService(0x1F, "imsp", "IMS Presence Service"),
    # iPhone: not listed
    QMIService(0x20, "imsvt", "IMS Videotelephony Service"),
    # iPhone: not listed
    QMIService(0x21, "imsa", "IMS Application Service"),

    QMIService(0x22, "coex", "Coexistence Service"),
    # 0x23 reserved for future use
    QMIService(0x24, "pdc", "Persistent Device Service"),
    # 0x25 reserved for future use

    # iPhone: not listed
    QMIService(0x26, "stx", "Simultaneous Transmit Service"),
    # iPhone: not listed
    QMIService(0x27, "bit", "Bearer Independent Transport Service"),

    # libqmi: "imsrtp" -> "IMS RTP Service"
    QMIService(0x28, "787", "5WI 787 Service"),

    # iPhone: not listed
    QMIService(0x29, "rfpre", "RF Radiated Performance Enhancement Service"),

    QMIService(0x2A, "dsd", "Data System Determination"),
    QMIService(0x2B, "ssctl", "Subsystem Control"),
    QMIService(0x2C, "mfse", "Modem File System Extended Service"),

    # iPhone: not listed
    QMIService(0x2F, "dpm", "Data Port Mapper Service"),

    QMIService(0x30, "dfs", "Data Filter Service"),
    QMIService(0x52, "ms", "Media Service Extension"),

    # libqmi: iPhone: not listed
    # QMIService(0xE0, "cat", "Card Application Toolkit Service (v1)"),

    # libqmi: "rms" -> "Remote Management Service"
    QMIService(0xE1, "audio", "Audio Service"),
    # libqmi: "oma" -> "Open Mobile Alliance device management service"
    QMIService(0xE2, "bsp", "Board Support Package Service"),
    # libqmi: "fox" -> "Foxconn General Modem Service"
    QMIService(0xE3, "ciq", "Carrier IQ Service"),
    QMIService(0xE4, "awd", "Apple Wireless Diagnostics"),
    QMIService(0xE5, "vinyl", "Vinyl Service"),
    # libqmi: "fota" -> "Firmware Over The Air Service"
    QMIService(0xE6, "mavims", "Mav 5WI Service"),
    # libqmi: "gms" -> "Telit General Modem Service"
    # iPhone: Full service name misspelled in binary code: "Enhnaced"
    QMIService(0xE7, "elqm", "Enhanced Link Quality Metric Service"),
    # libqmi: "gas" -> "Telit General Application Service"
    QMIService(0xE8, "p2p", "Mav P2P Service"),
    QMIService(0xE9, "apps", "BSP APPS Service"),
    # Apple's Satellite Service codenamed Stewie
    # https://www.bloomberg.com/news/articles/2021-08-30/apple-plans-to-add-satellite-features-to-iphones-for-emergencies
    QMIService(0xEA, "sft", "QMI Stewie Service"),

    # Special unknown service
    QMIService(0xFF, "unknown", "Unknown Service"),
]
