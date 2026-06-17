#pragma once

#include <iomanip>
#include <nlohmann/json.hpp>
#include <string>
#include <pcapplusplus/PcapFileDevice.h>

class FileWriter {
	std::optional<pcpp::PcapNgFileWriterDevice> pcapWriter;
	std::ofstream connLog;
	std::string filename;

	public:
		explicit FileWriter() {
			std::stringstream buffer;
			const auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
			const auto localTime = std::localtime(&time);
			buffer << std::put_time(localTime, "%Y_%m_%d_%H_%M_%S");
			this->filename = "output_" + buffer.str() + ".pcapng";
			pcapWriter.emplace(filename);
			if (!pcapWriter->open()) {
				throw std::runtime_error("Failed to open pcap file for writing");
			}
			connLog.open("conn_log.txt", std::ios::app);
			if (!connLog.is_open()) {
				throw std::runtime_error("Failed to open connection log file for writing");
			}
		}

		void writeConnectionLog(
			uint64_t connStartTime,
			uint64_t connCloseTime,
			const std::string& clientIp,
			const std::string& sourceIp,
			uint16_t srcPort,
			const std::string& dstIp,
			uint16_t dstPort,
			const std::string& protocol,
			uint64_t bytesSent,
			uint64_t bytesReceived,
			uint64_t packetsSent,
			uint64_t packetsReceived,
			std::set<std::string> domains,
			const nlohmann::json& ndpiResponse
		) {
			nlohmann::json json;
			json["connStartTime"] = connStartTime;
			json["connCloseTime"] = connCloseTime;
			json["clientIp"] = clientIp;
			json["sourceIp"] = sourceIp;
			json["srcPort"] = srcPort;
			json["dstIp"] = dstIp;
			json["dstPort"] = dstPort;
			json["protocol"] = protocol;
			json["bytesSent"] = bytesSent;
			json["bytesReceived"] = bytesReceived;
			json["packetsSent"] = packetsSent;
			json["packetsReceived"] = packetsReceived;

			nlohmann::json domainArray;
			for (const auto& domain : domains) {
				domainArray.push_back(domain);
			}
			json["domains"] = domainArray;
			json["ndpiResponse"] = ndpiResponse;

			connLog << json.dump() << std::endl;
		}

		void writePacket(const pcpp::RawPacket &packet) {
			pcapWriter->writePacket(packet);
		}

		void close() {
			pcapWriter->close();
			connLog.close();
		}
};
