#pragma once

#include <string>


class PcapWriter {
	public:
		PcapWriter(const std::string &filename) {
			pcapFileWriter = pcpp::PcapFileWriterDevice(filename.c_str());
			if (!pcapFileWriter.open()) {
				throw std::runtime_error("Failed to open pcap file for writing");
			}
		}

		void writePacket(const pcpp::Packet &packet) {
			pcapFileWriter.writePacket(packet);
		}

		void close() {
			pcapFileWriter.close();
		}
};
