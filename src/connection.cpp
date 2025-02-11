#include "connection.h"

#include <utility>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>

#include "client.h"
#include "logger.h"
#include "remote_socket_status.h"
#include "socket_utils.h"

Connection::Connection(
	std::shared_ptr<Client> client,
	pcpp::IPAddress src_ip,
	pcpp::IPAddress dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	Protocol protocol,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) :
	srcIp(src_ip),
	dstIp(dst_ip),
	srcPort(src_port),
	dstPort(dst_port),
	protocol(protocol),
	ndpiStr(ndpiStruct),
	client(client) {
	dataStream.reserve(5'000);

	ndpiFlow = std::unique_ptr<ndpi::ndpi_flow_struct, std::function<void(ndpi::ndpi_flow_struct *)>>(
		new ndpi::ndpi_flow_struct{},
		ndpi::ndpi_free_flow
	);
}

Connection::~Connection() {}

void Connection::sendToDeviceSocket(const pcpp::Packet &packet) {
	// Logger::get().log("Sending: " + PacketUtils::toString(packet));

	pcpp::RawPacket rawPacket{};
	rawPacket.initWithRawData(
		packet.getRawPacket()->getRawData(),
		packet.getRawPacket()->getRawDataLen(),
		packet.getRawPacket()->getPacketTimeStamp(),
		isIpv6() ? pcpp::LINKTYPE_IPV6 : pcpp::LINKTYPE_IPV4
	);
	pcapWriter->writePacket(rawPacket);

	lastPacketSentTime = std::chrono::system_clock::now();

	try {
		this->client->getTlsConnection()->send(
			std::span(packet.getRawPacketReadOnly()->getRawData(), packet.getRawPacketReadOnly()->getRawDataLen())
		);
	} catch (const std::exception &e) {
		log("failed to send data, closing connection");
		forcefullyCloseAll();
	}

	// this->client->getUnencryptedQueueToDevice().emplace(
	// 	packet.getRawPacketReadOnly()->getRawData(),
	// 	packet.getRawPacketReadOnly()->getRawData() + packet.getRawPacketReadOnly()->getRawDataLen()
	// );

	// u_long mode = 0;// Blocking mode
	// ioctlsocket(client->getClientSocket(), FIONBIO, &mode);
	//
	// // TODO problem s SocketUtils::writeExactly
	// int res = send(
	// 	client->getClientSocket(),
	// 	reinterpret_cast<const char *>(packet.getRawPacketReadOnly()->getRawData()),
	// 	packet.getRawPacketReadOnly()->getRawDataLen(),
	// 	0
	// );
	// const auto errCode = WSAGetLastError();
	// if (res == SOCKET_ERROR) {
	// 	log("sendToDeviceSocket send() returned: " + std::to_string(errCode));
	// }
	//
	// mode = 1;// Non-blocking mode
	// ioctlsocket(client->getClientSocket(), FIONBIO, &mode);
	//
	// // if (sent != packet.getRawPacketReadOnly()->getRawDataLen()) {
	// // 	log("sendToDeviceSocket send() failed: " + std::to_string(WSAGetLastError()));
	// // }
	// if (res == SOCKET_ERROR) {
	// 	if (errCode == WSAEWOULDBLOCK) {
	// 		log("sendToDeviceSocket send() failed: " + std::to_string(errCode));
	// 	}
	// 	log("sendToDeviceSocket send() failed: " + std::to_string(errCode));
	// } else if (res != packet.getRawPacketReadOnly()->getRawDataLen()) {
	// 	log("sendToDeviceSocket send() failed to send all data");
	// }

	processDpi(packet.getRawPacketReadOnly()->getRawData(), packet.getRawPacketReadOnly()->getRawDataLen());
	receivedPacketCount++;
}

void Connection::processDpi(const unsigned char *packetPtr, const unsigned short packetLen) {
	this->ndpiProtocol = ndpi::ndpi_detection_process_packet(
		this->ndpiStr,
		this->ndpiFlow.get(),
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
	if (remoteSocketStatus != status) {
		log("Remote socket status changed from " + remoteSocketStatusToString(remoteSocketStatus) + " to " + remoteSocketStatusToString(status));
	}
	remoteSocketStatus = status;
}

SOCKET Connection::getSocket() const {
	return socket;
}

const std::vector<uint8_t> & Connection::getDataStream() const {
	return dataStream;
}

const sockaddr_in & Connection::getDestSockAddr() const {
	return originSockAddr;
}

ndpi::ndpi_protocol Connection::getNdpiProtocol() const {
	return ndpiProtocol;
}

void Connection::setPcapWriter(const std::shared_ptr<pcpp::PcapNgFileWriterDevice> &pcapWriter) {
	Connection::pcapWriter = pcapWriter;
}

void Connection::setDnsManager(std::shared_ptr<DnsManager> dnsManager) {
	this->dnsManager = std::move(dnsManager);
}

std::unique_ptr<ndpi::ndpi_flow_struct, std::function<void(ndpi::ndpi_flow_struct*)>>& Connection::getNdpiFlow() {
	return ndpiFlow;
}

void Connection::log(const std::string &msg) const {
	Logger::get().log(
		std::format("[{}:{} -> {}:{} {}] {}", srcIp.toString(), srcPort, dstIp.toString(), dstPort, protocol == Protocol::TCP ? "TCP" : "UDP", msg)
	);
}

bool Connection::isIpv6() const {
	return srcIp.getType() == pcpp::IPAddress::IPv6AddressType;
}

std::unique_ptr<pcpp::Layer> Connection::buildIpLayer() {
	if (isIpv6()) {
		auto ipLayer = std::make_unique<pcpp::IPv6Layer>(dstIp.getIPv6(), srcIp.getIPv6());
		ipLayer->getIPv6Header()->hopLimit = 64;
		ipLayer->getIPv6Header()->nextHeader = this->protocol == Protocol::TCP ? pcpp::PACKETPP_IPPROTO_TCP : pcpp::PACKETPP_IPPROTO_UDP;

		return ipLayer;
	}

	auto ipLayer = std::make_unique<pcpp::IPv4Layer>(dstIp.getIPv4(), srcIp.getIPv4());
	ipLayer->getIPv4Header()->timeToLive = 64;
	ipLayer->getIPv4Header()->protocol = this->protocol == Protocol::TCP ? pcpp::PACKETPP_IPPROTO_TCP : pcpp::PACKETPP_IPPROTO_UDP;

	return ipLayer;
}

std::shared_ptr<Client> Connection::getClient() const {
	return client;
}

unsigned long long Connection::getOrderNum() const {
	return orderNum;
}

void Connection::setOrderNum(unsigned long long order_num) {
	orderNum = order_num;
}

void Connection::closeSocketAndInvalidate() {
	closesocket(socket);
	socket = 0;
}
