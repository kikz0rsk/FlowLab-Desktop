#pragma once

#include <iomanip>
#include <json/json.h>
#include <string>
#include <pcapplusplus/PcapFileDevice.h>

class FileWriter {
	std::optional<pcpp::PcapNgFileWriterDevice> pcapWriter;
	std::ofstream connLog;
	std::string filename;
	Json::StreamWriterBuilder jsonWriter;

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
			jsonWriter["indentation"] = "";
		}

		void writeConnectionLog(
			uint64_t timestamp,
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
			const Json::Value& ndpiResponse
		) {
			Json::Value json;
			json["timestamp"] = timestamp;
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
			Json::Value domainArray(Json::arrayValue);
			for (const auto& domain : domains) {
				domainArray.append(domain);
			}
			json["domains"] = domainArray;
			json["ndpiResponse"] = ndpiResponse;

			connLog << Json::writeString(jsonWriter, json) << std::endl;
		}

		void writePacket(const pcpp::RawPacket &packet) {
			pcapWriter->writePacket(packet);
		}

		void close() {
			pcapWriter->close();
			connLog.close();
		}
};
