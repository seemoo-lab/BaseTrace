# BaseTrace

![BaseTrace Logo](./logo.svg)

A framework of tools for researching the interface connecting the iPhone's application processor with its baseband chipset.

Read more about the different baseband chips installed in iPhones
on [The Apple Wiki](https://theapplewiki.com/wiki/Baseband_Device).

The [CellGuard](https://github.com/seemoo-lab/CellGuard) iOS app for rogue base station detection builds upon our insights gained from applying BaseTrace. 
The app is stored in a dedicated GitHub repository.

## Tools

### Location Databases

A location database stores approximate locations for a given Wi-Fi access point or cell of the cellular network.
Read more about how different open location databases compare with Apple's database in the Catch You Cause I Can paper.

#### [Apple Location Services](./apple-location-services)

A standalone client for Apple's location database.

### Qualcomm Basebands

iPhones with Qualcomm basebands use the **Qualcomm MSM Interface (QMI)** protocol for iOS-baseband-communication.
Read more about the iPhone's baseband architecture in the Catch You Cause I Can paper.

#### [libqmi iOS Extensions](./libqmi-ios-ext)

iOS-specific protocol extension for the library [libqmi](https://gitlab.freedesktop.org/mobile-broadband/libqmi) used by QMI Dissect and CellGuard.

#### [QMI Dissect](./qmi-dissect)

A Wireshark dissector for iPhones with a Qualcomm baseboard.

Works with all iPhones.

#### [QMI Inject](./qmi-inject)

A tool to establish a direct communication link with the iPhone's baseband, enabling you to inject custom packets and receive the baseband's responses.

Requires a jailbroken iPhone.

### Intel Basebands

iPhones with Intels basebands use the **Apple Remote Invocation (ARI)** protocol for iOS-baseband-communication.
Read more about the protocol in Tobias' bachelor thesis and his paper ARIstoteles.

#### [ARIstoles](https://github.com/seemoo-lab/aristoteles/tree/master)

A Wireshark dissector for iPhones with an Intel baseband.

Works with all iPhones.

## Publications

- [Arnold L., Hollick M., Classen J. (2024): "Catch You Cause I Can: Busting Rogue Base Stations using CellGuard and the Apple Cell Location Database"](https://doi.org/10.1145/3678890.3678898)
- [Kröll T., Kleber S., Kargl F., Hollick M., Classen J. (2021): "ARIstoteles – Dissecting Apple’s Baseband Interface"](https://doi.org/10.1007/978-3-030-88418-5_7)
- [Kröll T. (2021): "ARIstoteles: iOS Baseband Interface Protocol Analysis"](https://tuprints.ulb.tu-darmstadt.de/id/eprint/19397)
