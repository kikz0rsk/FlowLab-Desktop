#include "connection.h"

#include "packet_utils.h"
#include "remote_socket_status.h"

Connection::Connection(
	pcpp::IPAddress originHostIp,
	uint16_t originHostPort,
	pcpp::IPAddress src_ip,
	pcpp::IPAddress dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	Protocol protocol,
	SOCKET deviceSocket,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) :
	originHostIp(originHostIp),
	originHostIpStr(originHostIp.toString()),
	originHostPort(originHostPort),
	srcIp(src_ip),
	dstIp(dst_ip),
	srcPort(src_port),
	dstPort(dst_port),
	protocol(protocol),
	deviceSocket(deviceSocket),
	ndpiStr(ndpiStruct) {
	dataStream.reserve(5'000);
	originSockAddr = sockaddr_in{AF_INET, htons(originHostPort)};
	originSockAddr.sin_addr.s_addr = inet_addr(originHostIpStr.c_str());

	ndpiFlow = (ndpi::ndpi_flow_struct *) calloc(1, sizeof(ndpi::ndpi_flow_struct));
}

Connection::~Connection() {
	ndpi::ndpi_free_flow(ndpiFlow);
}

void Connection::sendToDeviceSocket(const pcpp::Packet &packet) {
	Logger::get().log("Sending: " + PacketUtils::toString(packet));

	pcpp::RawPacket rawPacket{};
	rawPacket.initWithRawData(packet.getRawPacket()->getRawData(), packet.getRawPacket()->getRawDataLen(), packet.getRawPacket()->getPacketTimeStamp(), pcpp::LINKTYPE_IPV4);
	pcapWriter->writePacket(rawPacket);

	sendto(
		deviceSocket,
		reinterpret_cast<const char *>(packet.getRawPacketReadOnly()->getRawData()),
		packet.getRawPacketReadOnly()->getRawDataLen(),
		0,
		(SOCKADDR *) &originSockAddr,
		sizeof(originSockAddr)
	);

	processDpi(packet.getRawPacketReadOnly()->getRawData(), packet.getRawPacketReadOnly()->getRawDataLen());
	receivedPacketCount++;
}

void Connection::processDpi(const unsigned char *packetPtr, const unsigned short packetLen) {
	this->ndpiProtocol = ndpi::ndpi_detection_process_packet(
		this->ndpiStr,
		this->ndpiFlow,
		packetPtr,
		packetLen,
		std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()),
		nullptr
	);
}

bool Connection::shouldClose() const {
	if (lastPacketSentTime.has_value()) {
		return std::chrono::system_clock::now() - *lastPacketSentTime > std::chrono::seconds(30);
	} else {
		return std::chrono::system_clock::now() - createdTime > std::chrono::seconds(30);
	}
}

std::shared_lock<std::shared_mutex> Connection::getReadLock() {
	return std::shared_lock(mutex);
}

std::unique_lock<std::shared_mutex> Connection::getWriteLock() {
	return std::unique_lock(mutex);
}

const Protocol & Connection::getProtocol() const {
	return protocol;
}

const std::chrono::system_clock::time_point & Connection::getCreatedTime() const {
	return createdTime;
}

const std::optional<std::chrono::system_clock::time_point> & Connection::getLastPacketSentTime() const {
	return lastPacketSentTime;
}

const pcpp::IPAddress & Connection::getSrcIp() const {
	return srcIp;
}

void Connection::setSrcIp(const pcpp::IPAddress &srcIp) {
	Connection::srcIp = srcIp;
}

const pcpp::IPAddress & Connection::getDstIp() const {
	return dstIp;
}

void Connection::setDstIp(const pcpp::IPAddress &dstIp) {
	Connection::dstIp = dstIp;
}

uint16_t Connection::getSrcPort() const {
	return srcPort;
}

void Connection::setSrcPort(uint16_t srcPort) {
	Connection::srcPort = srcPort;
}

uint16_t Connection::getDstPort() const {
	return dstPort;
}

void Connection::setDstPort(uint16_t dstPort) {
	Connection::dstPort = dstPort;
}

RemoteSocketStatus Connection::getRemoteSocketStatus() const {
	return remoteSocketStatus;
}

void Connection::setRemoteSocketStatus(RemoteSocketStatus status) {
	remoteSocketStatus = status;
}

SOCKET Connection::getSocket() const {
	return socket;
}

const std::vector<uint8_t> & Connection::getDataStream() const {
	return dataStream;
}

const pcpp::IPAddress & Connection::getOriginHostIp() const {
	return originHostIp;
}

uint16_t Connection::getOriginHostPort() const {
	return originHostPort;
}

const sockaddr_in & Connection::getDestSockAddr() const {
	return originSockAddr;
}

ndpi::ndpi_protocol Connection::getNdpiProtocol() const {
	return ndpiProtocol;
}

void Connection::setPcapWriter(const std::shared_ptr<pcpp::PcapFileWriterDevice> &pcapWriter) {
	Connection::pcapWriter = pcapWriter;
}
