
# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2023-03-21
### Added
- Initial release of the TCP and UDP client.

### Changed
- N/A

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- N/A

### Limitations
- The TCP and UDP client work under the assumption that the protocol was followed - the server sent the response in the correct format.
- Timeout for connection is not implemented.
- Possible memory leaks in udp_client.c and tcp_client.c
