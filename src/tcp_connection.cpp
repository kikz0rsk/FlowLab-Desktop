#include "tcp_connection.h"

#include <random>
#include <iostream>
#include <utility>
#include <regex>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PacketUtils.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLLayer.h>
#include <tracy/Tracy.hpp>
#include <botan/x509_ext.h>

#include "logger.h"
#include "server_forwarder.h"
#include "client_forwarder.h"
#include "connection_manager.h"

TcpConnection::TcpConnection(
	std::shared_ptr<ProxyService> proxyService,
	std::shared_ptr<Client> client,
	const pcpp::IPAddress &src_ip,
	const pcpp::IPAddress &dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) : Connection(std::move(proxyService), std::move(client), src_ip, dst_ip, src_port, dst_port, Protocol::TCP, ndpiStruct),
		destSocket(proxyService->getIoContext()) {}

TcpConnection::~TcpConnection() {
	TcpConnection::gracefullyCloseRemoteSocket();
}

void TcpConnection::resetState() {
	ackNumber = 0;
	ourSequenceNumber = 0;
	ourWindowSize = 65'535;
	remoteWindowSize = 65'535;
	finSequenceNumber = 0;
	unAckedBytes = 0;
	lastRemoteAckedNum = 0;
	windowSizeMultiplier = 1;
	maxSegmentSize = DEFAULT_MAX_SEGMENT_SIZE;
	shouldSendFinOnAckedEverything = false;
	clientTlsForwarder.reset();
	serverTlsForwarder.reset();
	hasCertificate = false;
	doTlsRelay = false;
	serverNameIndication.clear();
	tlsBuffer.clear();
	domains.clear();
	tlsRelayStatus = "Unknown";
	lastTag.clear();
	clientHandshakeRecordSize = 0;
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	setTcpStatus(TcpStatus::CLOSED);
}

void TcpConnection::gracefullyCloseRemoteSocket() {
	ZoneScoped;

	if (this->remoteSocketStatus == RemoteSocketStatus::CLOSED) {
		return;
	}

	this->destSocket.shutdown(boost::asio::socket_base::shutdown_both);
	this->destSocket.close();
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	logToFile();
}

void TcpConnection::sendFinAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->finFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

void TcpConnection::sendSynAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->synFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::TcpOptionBuilder mss(pcpp::TcpOptionEnumType::Mss, static_cast<uint16_t>(DEFAULT_MAX_SEGMENT_SIZE));
	pcpp::TcpOptionBuilder winScale(pcpp::TcpOptionEnumType::Window, static_cast<uint8_t>(8));
	pcpp::TcpOptionBuilder noop(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop);

	tcpLayer->addTcpOption(winScale);
	tcpLayer->addTcpOption(mss);
	tcpLayer->addTcpOption(noop);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

boost::asio::awaitable<void> TcpConnection::processPacketFromDevice(pcpp::Layer *networkLayer) {
	ZoneScoped;
	auto tcpLayer = dynamic_cast<pcpp::TcpLayer *>(networkLayer->getNextLayer());
	auto packetSequenceNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber);
	auto packetAckNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->ackNumber);
	if (remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		log("Waiting for connection to be established: " + tcpLayer->toString());

		co_return;
	}

	processDpi(networkLayer->getDataPtr(0), networkLayer->getDataLen());
	++sentPacketCount;

	if (tcpLayer->getTcpHeader()->synFlag == 1) {
		if (this->tcpStatus == TcpStatus::SYN_RECEIVED) {
			co_await openSocket();

			co_return;
		}
		if (this->tcpStatus != TcpStatus::CLOSED) {
			co_return;
		}
		resetState();
		this->doTlsRelay = pcpp::SSLLayer::isSSLPort(dstPort) && this->proxyService && this->proxyService->getEnableTlsRelay();

		ackNumber = packetSequenceNumber + 1;
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<std::mt19937::result_type> distrib(1, std::numeric_limits<uint32_t>::max());
		ourSequenceNumber = distrib(gen);

		setTcpStatus(TcpStatus::SYN_RECEIVED);

		const auto windowScaleOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Window);
		if (!windowScaleOpt.isNull()) {
			windowSizeMultiplier = 1 << windowScaleOpt.getValueAs<uint8_t>();
		}

		const auto mssOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Mss);
		if (!mssOpt.isNull()) {
			maxSegmentSize = pcpp::netToHost16(mssOpt.getValueAs<uint16_t>());
		}
		remoteWindowSize = pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) * windowSizeMultiplier;

		co_await openSocket();

		co_return;
	}

	remoteWindowSize = pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) * windowSizeMultiplier;

	if (tcpLayer->getTcpHeader()->ackFlag == 1) {
		if (packetAckNumber >= lastRemoteAckedNum) {
			lastRemoteAckedNum = packetAckNumber;
		}
		const long long unAcked = static_cast<long long>(ourSequenceNumber.load()) - static_cast<long long>(lastRemoteAckedNum);
		unAckedBytes = unAcked > 0 ? unAcked : 0;
		if (tcpStatus == TcpStatus::SYN_RECEIVED) {
			setTcpStatus(TcpStatus::ESTABLISHED);
		} else if (tcpStatus == TcpStatus::FIN_WAIT_1 && lastRemoteAckedNum > finSequenceNumber) {
			setTcpStatus(TcpStatus::FIN_WAIT_2);
		} else if (tcpStatus == TcpStatus::CLOSE_WAIT && lastRemoteAckedNum > finSequenceNumber) {
			setTcpStatus(TcpStatus::CLOSED);
			gracefullyCloseRemoteSocket();
		}
	}

	if (packetSequenceNumber != ackNumber) {
		// packet is out of order
		if (tcpLayer->getTcpHeader()->rstFlag == 1) {
			forcefullyCloseAll();

			co_return;
		}

		log(
			"Received unexpected packet, this packet seq="
			+ std::to_string(packetSequenceNumber)
			+ ", expected="
			+ std::to_string(ackNumber)
		);
		sendAck();

		co_return;
	}

	const size_t dataSize = tcpLayer->getLayerPayloadSize();
	if (dataSize > 0) {
		const auto dataPtr = tcpLayer->getLayerPayload();
		{
			ZoneScopedN("dataStreamWrite");
			auto writeLock = getWriteLock();
			if (dataStream.size() < 1'000'000) {
				dataStream.insert(dataStream.end(), dataPtr, dataPtr + dataSize);
			}
		}

		const auto span = std::span(dataPtr, dataSize);

		if (doTlsRelay) {
			if (!hasCertificate) {
				if (const auto sslLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(networkLayer->getNextLayer()->getNextLayer())) {
					this->clientHandshakeRecordSize = pcpp::netToHost16(sslLayer->getRecordLayer()->length);
				}
				this->tlsBuffer.insert(this->tlsBuffer.end(), span.begin(), span.end());
				if (this->tlsBuffer.size() >= this->clientHandshakeRecordSize) {
					pcpp::Packet dummyPacket;
					pcpp::SSLHandshakeLayer sslHandshakeLayer(tlsBuffer.data(), tlsBuffer.size(), nullptr, &dummyPacket);
					if (const auto clientHello = sslHandshakeLayer.getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>()) {
						if (const auto sniExt = dynamic_cast<pcpp::SSLServerNameIndicationExtension *>(clientHello->getExtensionOfType(pcpp::SSL_EXT_SERVER_NAME)); sniExt != nullptr) {
							serverNameIndication = sniExt->getHostName();
							if (!serverNameIndication.empty()) {
								domains.insert(serverNameIndication);
							}
						}
					}
					initTlsClient();
					if (this->proxyService) {
						proxyService->getConnectionManager()->markAsTlsConnection(std::dynamic_pointer_cast<TcpConnection>(shared_from_this()));
					}
				}
			} else {
				if (!this->tlsBuffer.empty()) {
					this->serverTlsForwarder->getServer()->received_data(std::span(this->tlsBuffer.begin(), this->tlsBuffer.end()));
					this->tlsBuffer.clear();
				}
				this->serverTlsForwarder->getServer()->received_data(span);
			}
		} else {
			co_await sendDataToRemote(span);
		}
	}

	ackNumber = packetSequenceNumber;
	if (dataSize > 0) {
		ackNumber += dataSize;
		sendAck();
	}

	if (tcpLayer->getTcpHeader()->rstFlag == 1) {
		forcefullyCloseAll();

		co_return;
	}

	if (tcpLayer->getTcpHeader()->finFlag == 1) {
		if (tcpStatus == TcpStatus::FIN_WAIT_2) {
			ackNumber += 1;
			sendAck();

			setTcpStatus(TcpStatus::CLOSED);
			gracefullyCloseRemoteSocket();

			co_return;
		} else if (tcpStatus == TcpStatus::ESTABLISHED) {
			log("Remote side is initiating TCP close");
			if (unAckedBytes > 0) {
				ackNumber += 1;
				sendAck();
				shouldSendFinOnAckedEverything = true;
			} else {
				ackNumber += 1;
				sendFinAck();
				finSequenceNumber = ourSequenceNumber.load();
				ourSequenceNumber += 1;
				setTcpStatus(TcpStatus::CLOSE_WAIT);
			}

			co_return;
		}
	}

	if (
		tcpLayer->getTcpHeader()->ackFlag == 1 && unAckedBytes == 0 && shouldSendFinOnAckedEverything
		&& tcpStatus != TcpStatus::FIN_WAIT_1 && tcpStatus != TcpStatus::FIN_WAIT_2 && tcpStatus != TcpStatus::CLOSE_WAIT
	) {
		sendFinAck();
		setTcpStatus(TcpStatus::FIN_WAIT_1);
		finSequenceNumber = ourSequenceNumber.load();
		ourSequenceNumber += 1;
	}
}

boost::asio::awaitable<void> TcpConnection::openSocket() {
	ZoneScoped;
	if (remoteSocketStatus == RemoteSocketStatus::ESTABLISHED) {
		gracefullyCloseRemoteSocket();
	}

	try {
		this->remoteSocketStatus = RemoteSocketStatus::INITIATING;
		co_await this->destSocket.async_connect(
			boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(this->dstIp.toString()), this->dstPort),
			boost::asio::use_awaitable
		);
		Logger::get().log("Connected to remote socket");
		setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
		sendSynAck();
		ourSequenceNumber += 1;
		connStartTime = std::chrono::system_clock::now();
	} catch (const boost::system::system_error& err) {
		log(std::format("Failed to connect: {}", err.what()));
		sendRst(true);
		gracefullyCloseRemoteSocket();
		setTcpStatus(TcpStatus::CLOSED);

		co_return;
	}
}

void TcpConnection::sendAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

boost::asio::awaitable<void> TcpConnection::sendDataToRemote(std::span<const uint8_t> data) {
	ZoneScoped;
	sentBytes += data.size();
	co_await boost::asio::async_write(this->destSocket, boost::asio::buffer(data), boost::asio::use_awaitable);
}

boost::asio::awaitable<std::vector<uint8_t>> TcpConnection::read() {
	ZoneScoped;
	if (remoteSocketStatus != RemoteSocketStatus::ESTABLISHED) {
		co_return std::vector<uint8_t>{};
	}

	long long bytesToRead = static_cast<long long>(this->remoteWindowSize) - static_cast<long long>(unAckedBytes) - 2 * static_cast<long long>(maxSegmentSize);
	if (bytesToRead <= 0) {
		co_return std::vector<uint8_t>{};
	}

	bytesToRead = bytesToRead < maxSegmentSize ? bytesToRead : maxSegmentSize;

	std::vector<char> buffer(bytesToRead);

	unsigned long long length;
	try {
		length = co_await this->destSocket.async_read_some(boost::asio::buffer(buffer, bytesToRead), boost::asio::use_awaitable);
	} catch (const boost::system::system_error& err) {
		log(std::format("read failed: {}", err.what()));
		sendRst(true);
		setTcpStatus(TcpStatus::CLOSED);
		gracefullyCloseRemoteSocket();

		co_return std::vector<uint8_t>{};
	}

	if (length == 0) {
		// Connection closed
		gracefullyCloseRemoteSocket();
		if (
			tcpStatus == TcpStatus::FIN_WAIT_1
			|| tcpStatus == TcpStatus::FIN_WAIT_2 || tcpStatus == TcpStatus::CLOSE_WAIT || shouldSendFinOnAckedEverything
		) {
			co_return std::vector<uint8_t>{};
		}

		if (unAckedBytes > 0) {
			log("Waiting for ack on everything before closing connection");
			shouldSendFinOnAckedEverything = true;
		} else {
			log("We are initiating TCP close");
			sendFinAck();
			setTcpStatus(TcpStatus::FIN_WAIT_1);
			finSequenceNumber = ourSequenceNumber.load();
			ourSequenceNumber += 1;
		}

		co_return std::vector<uint8_t>{};
	}

	{
		auto writeLock = getWriteLock();
		if (dataStream.size() < 1'000'000) {
			dataStream.insert(dataStream.end(), buffer.begin(), buffer.begin() + length);
		}
	}
	receivedBytes += length;

	if (doTlsRelay && this->clientTlsForwarder && this->clientTlsForwarder->getClient()) {
		this->clientTlsForwarder->getClient()->received_data(std::span(reinterpret_cast<uint8_t *>(buffer.data()), length));

		co_return std::vector<uint8_t>{};
	}

	co_return std::vector<uint8_t>{buffer.begin(), buffer.begin() + length};
}

// TODO delete
void TcpConnection::writeEvent() {
	if (this->remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
		sendSynAck();
		ourSequenceNumber += 1;
		connStartTime = std::chrono::system_clock::now();
	}
}

// TODO delete
void TcpConnection::exceptionEvent() {
	Logger::get().log("Exception event");
	if (this->remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		Logger::get().log("Exception event: Failed to open");
		sendRst(true);
		gracefullyCloseRemoteSocket();
		setTcpStatus(TcpStatus::CLOSED);
	}
}

std::unique_ptr<pcpp::Packet> TcpConnection::encapsulateResponseDataToPacket(std::span<const uint8_t> data) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->pshFlag = 1;
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);
	auto payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

	auto tcpPacket = std::make_unique<pcpp::Packet>(data.size() + 100);
	tcpPacket->addLayer(ipLayer, true);
	tcpPacket->addLayer(tcpLayer, true);
	tcpPacket->addLayer(payloadLayer, true);

	tcpPacket->computeCalculateFields();

	return tcpPacket;
}

void TcpConnection::sendDataToDeviceSocket(std::span<const uint8_t> data) {
	ZoneScoped;

	size_t offset = 0;
	unsigned int maxSegmentSize = this->maxSegmentSize < DEFAULT_MAX_SEGMENT_SIZE ? this->maxSegmentSize : DEFAULT_MAX_SEGMENT_SIZE;
	while (offset < data.size()) {
		const unsigned int length = std::min(offset + maxSegmentSize, data.size()) - offset;
		const bool isLast = offset + length == data.size();
		const auto packet = encapsulateResponseDataToPacket(std::span(data.begin() + offset, data.begin() + offset + length));
		if (!packet) {
			break;
		}
		if (isLast) {
			packet->getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->pshFlag = 1;
		}

		// log(
		// 	"Sending to: " + originHostIp.toString() + ":" + std::to_string(originHostPort) + " " + PacketUtils::toString(*packet)
		// );

		sendToDeviceSocket(*packet);

		ourSequenceNumber += length;
		unAckedBytes += length;
		offset += length;
	}
}

unsigned int TcpConnection::getAckNumber() const {
	return ackNumber;
}

std::atomic_uint32_t & TcpConnection::getOurSequenceNumber() {
	return ourSequenceNumber;
}

void TcpConnection::sendRst(bool ack) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto tcpLayer = new pcpp::TcpLayer(dstPort, srcPort);
	tcpLayer->getTcpHeader()->rstFlag = 1;
	if (ack) {
		tcpLayer->getTcpHeader()->ackFlag = 1;
	}
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(ourSequenceNumber.load());
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(ourWindowSize);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDeviceSocket(packet);
}

TcpStatus TcpConnection::getTcpStatus() const {
	return tcpStatus.load();
}

void TcpConnection::setTcpStatus(TcpStatus tcpStatus) {
	if (this->tcpStatus != tcpStatus) {
		log("TCP status changed from " + tcpStatusToString(this->tcpStatus) + " to " + tcpStatusToString(tcpStatus));
	}
	this->tcpStatus = tcpStatus;
}

void TcpConnection::forcefullyCloseAll() {
	if (this->remoteSocketStatus != RemoteSocketStatus::CLOSED) {
		setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	}
	if (this->tcpStatus != TcpStatus::CLOSED) {
		sendRst(true);
	}
	this->destSocket.close();
	setTcpStatus(TcpStatus::CLOSED);
	logToFile();
}

bool TcpConnection::canRemove() const {
	return tcpStatus == TcpStatus::CLOSED && remoteSocketStatus == RemoteSocketStatus::CLOSED;
}

void TcpConnection::onTlsClientDataToSend(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Client] Sending " + std::to_string(data.size()) + " bytes to remote");
	this->sendDataToRemote(data);
}

void TcpConnection::onTlsClientDataReceived(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Client] Received " + std::to_string(data.size()) + " bytes from remote");

	if (this->lastTag != SERVER_TAG) {
		const std::string tag = std::format("\n{}\n", SERVER_TAG);
		this->unencryptedFileStream.write(tag.c_str(), tag.size());
		this->lastTag = SERVER_TAG;
	}

	this->unencryptedFileStream.write(reinterpret_cast<const char *>(data.data()), data.size());
	this->unencryptedFileStream.flush();
	this->unencryptedStream.insert(unencryptedStream.end(), data.begin(), data.end());
	this->serverTlsForwarder->getServer()->send(data);
}

void TcpConnection::onTlsServerDataReceived(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Server] Received " + std::to_string(data.size()) + " bytes from client");

	if (this->lastTag != CLIENT_TAG) {
		const std::string tag = std::format("\n{}\n", CLIENT_TAG);
		this->unencryptedFileStream.write(tag.c_str(), tag.size());
		this->lastTag = CLIENT_TAG;
	}

	std::vector modifiedData(data.begin(), data.end());
	regexReplace(
		modifiedData,
		std::regex(
			"\r\nAccept-Encoding: .+\r\n",
			std::regex_constants::icase
		),
		"\r\nAccept-Encoding: identity\r\n"
	);

	this->unencryptedFileStream.write(reinterpret_cast<const char *>(modifiedData.data()), modifiedData.size());
	this->unencryptedFileStream.flush();
	this->unencryptedStream.insert(unencryptedStream.end(), modifiedData.begin(), modifiedData.end());
	this->clientTlsForwarder->getClient()->send(modifiedData);
}

void TcpConnection::onTlsServerDataToSend(std::span<const uint8_t> data) {
	Logger::get().log("[TLS Proxy Server] Sending " + std::to_string(data.size()) + " bytes to client");
	this->sendDataToDeviceSocket(data);
}

void TcpConnection::onTlsServerAlert(Botan::TLS::Alert alert) {
	log(this->serverNameIndication + " TLS Server alert: " + alert.type_string());
	if (alert.is_fatal()) {
		tlsRelayStatus = "Device Fail: " + alert.type_string();
	}
	if (this->clientTlsForwarder && this->clientTlsForwarder->getClient()) {
		this->clientTlsForwarder->getClient()->send_alert(alert);
	}
}

void TcpConnection::onTlsClientAlert(Botan::TLS::Alert alert) {
	log(this->serverNameIndication + " TLS Client alert: " + alert.type_string());
	if (alert.is_fatal()) {
		tlsRelayStatus = "Remote Fail: " + alert.type_string();
	}
	if (this->serverTlsForwarder && this->serverTlsForwarder->getServer()) {
		this->serverTlsForwarder->getServer()->send_alert(alert);
	}
}

void TcpConnection::onTlsClientGotCertificate(const Botan::X509_Certificate &cert) {
	Logger::get().log("Received certificate: " + cert.to_string());
	this->initTlsServer(cert);
	this->hasCertificate = true;
	tlsRelayStatus = "Received certificate";
	if (!cert.subject_info("X520.CommonName").empty()) {
		for (const auto& domain : cert.subject_info("X520.CommonName")) {
			if (domain.empty()) {
				continue;
			}
			domains.insert(domain);
		}
	}
	const auto& altName = cert.subject_alt_name();
	if (altName.has_items() && !altName.dn().to_string().empty()) {
		domains.insert(altName.dn().to_string());
	}
	this->filePath = std::format(
		"tls-streams/{}_{}_{}.bin",
		this->client->getClientIp().toString(),
		srcPort,
		domains.empty() ? this->dstIp.toString() : std::string(*domains.begin())
	);
	this->filePath = std::regex_replace(this->filePath, std::regex("(:|\\*)"), "_");
	this->unencryptedFileStream = std::ofstream(this->filePath, std::ios::binary | std::ios::app);
	if (!this->unencryptedFileStream) {
		Logger::get().log("Failed to open stream");
	}
	if (!this->tlsBuffer.empty()) {
		const std::vector data(tlsBuffer.begin(), tlsBuffer.end());
		this->serverTlsForwarder->getServer()->received_data(data);
		this->tlsBuffer.clear();
	}
}

void TcpConnection::initTlsClient() {
	this->clientTlsForwarder = std::make_shared<ClientForwarder>(
		this->serverNameIndication,
		this->dstPort,
		[this](uint64_t seq_no, std::span<const uint8_t> data) {
			this->onTlsClientDataReceived(data);
		},
		[this](std::span<const uint8_t> data) {
			this->onTlsClientDataToSend(data);
		},
		[this](Botan::TLS::Alert alert) {
			this->onTlsClientAlert(alert);
		},
		[this](const Botan::X509_Certificate &cert) {
			this->onTlsClientGotCertificate(cert);
		}
	);
}

void TcpConnection::initTlsServer(const Botan::X509_Certificate &cert) {
	this->serverTlsForwarder = std::make_shared<ServerForwarder>(
		cert,
		[this](uint64_t seq_no, std::span<const uint8_t> data) {
			this->onTlsServerDataReceived(data);
		},
		[this](std::span<const uint8_t> data) {
			this->onTlsServerDataToSend(data);
		},
		[this](Botan::TLS::Alert alert) {
			this->onTlsServerAlert(alert);
		},
		[this] {
			this->onTlsServerSuccess();
		}
	);
}

const std::string & TcpConnection::getServerNameIndication() {
	return serverNameIndication;
}

const std::deque<uint8_t> & TcpConnection::getUnencryptedStream() {
	return unencryptedStream;
}

const std::string & TcpConnection::getTlsRelayStatus() const {
	return tlsRelayStatus;
}

void TcpConnection::onTlsServerSuccess() {
	this->tlsRelayStatus = "Success";
}

std::set<std::string> & TcpConnection::getDomains() {
	return domains;
}

void TcpConnection::logToFile() {
	if (tcpStatus != TcpStatus::CLOSED || remoteSocketStatus != RemoteSocketStatus::CLOSED) {
		return;
	}
	if (this->unencryptedFileStream.tellp() == 0) {
		this->unencryptedFileStream.close();
		std::remove(this->filePath.c_str());
	}
	if (this->unencryptedFileStream.is_open()) {
		this->unencryptedFileStream.close();
	}
	Connection::logToFile();
}
