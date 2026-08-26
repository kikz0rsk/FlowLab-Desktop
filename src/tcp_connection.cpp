#include "tcp_connection.h"

#include <algorithm>
#include <random>
#include <iostream>
#include <utility>
#include <regex>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PacketUtils.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <tracy/Tracy.hpp>
#include <botan/x509_ext.h>

#include "logger.h"
#include "server_forwarder.h"
#include "connection_manager.h"
#include "defer.h"
#include "iprocessor.h"
#include "log_processor.h"
#include "tls_processor.h"

TcpConnection::TcpConnection(
	std::shared_ptr<ProxyService> proxyService,
	std::shared_ptr<Client> client,
	const pcpp::IPAddress& src_ip,
	const pcpp::IPAddress& dst_ip,
	uint16_t src_port,
	uint16_t dst_port,
	ndpi::ndpi_detection_module_struct *ndpiStruct
) : Connection(proxyService, std::move(client), src_ip, dst_ip, src_port, dst_port, Protocol::TCP, ndpiStruct),
		destSocket(proxyService->getIoContext()) {
	this->processors.emplace_back(std::make_shared<TlsProcessor>());
	this->processors.emplace_back(std::make_shared<LogProcessor>());
}

TcpConnection::~TcpConnection() {
	TcpConnection::closeSocketSoft();
}

void TcpConnection::resetState() {
	this->tcpState = TcpState{};
	this->maxSegmentSize = DEFAULT_MAX_SEGMENT_SIZE;
	this->doTlsRelay = false;
	this->domains.clear();
	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	setTcpStatus(TcpStatus::CLOSED);

	const ProcessorInitContext context{
		.connection = shared_from_this(),
	};
	for (const auto& p : this->processors) {
		p->init(context);
	}
}

void TcpConnection::closeSocketSoft() {
	ZoneScoped;

	if (this->remoteSocketStatus == RemoteSocketStatus::CLOSED) {
		return;
	}

	try {
		this->destSocket.shutdown(boost::asio::socket_base::shutdown_both);
		this->destSocket.close();
	} catch (const boost::system::system_error& e) {
		log(std::format("Error closing socket: {}", e.what()));
	}

	setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	logToFile();
}

void TcpConnection::sendFinAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto *tcpLayer = buildTcpLayer().release();
	tcpLayer->getTcpHeader()->finFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDevice(packet);
}

void TcpConnection::sendSynAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto *tcpLayer = buildTcpLayer().release();
	tcpLayer->getTcpHeader()->synFlag = 1;
	tcpLayer->getTcpHeader()->ackFlag = 1;

	const pcpp::TcpOptionBuilder mss(pcpp::TcpOptionEnumType::Mss, static_cast<uint16_t>(DEFAULT_MAX_SEGMENT_SIZE));
	const pcpp::TcpOptionBuilder winScale(pcpp::TcpOptionEnumType::Window, static_cast<uint8_t>(8));
	const pcpp::TcpOptionBuilder noop(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop);

	tcpLayer->addTcpOption(winScale);
	tcpLayer->addTcpOption(mss);
	tcpLayer->addTcpOption(noop);

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDevice(packet);
}

boost::asio::awaitable<void> TcpConnection::processPacketFromDevice(pcpp::Layer *networkLayer) {
	ZoneScoped;
	const auto *tcpLayer = dynamic_cast<pcpp::TcpLayer *>(networkLayer->getNextLayer());
	if (tcpLayer == nullptr) {
		co_return;
	}

	auto packetSequenceNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->sequenceNumber);

	if (remoteSocketStatus == RemoteSocketStatus::INITIATING) {
		log("Waiting for connection to be established: " + tcpLayer->toString());

		co_return;
	}

	processDpi(networkLayer->getDataPtr(0), networkLayer->getDataLen());
	++sentPacketCount;

	if (tcpLayer->getTcpHeader()->synFlag == 1) {
		if (this->tcpStatus != TcpStatus::CLOSED) {
			co_return;
		}

		resetState();
		this->doTlsRelay = pcpp::SSLLayer::isSSLPort(dstPort) && this->proxyService && this->proxyService->getEnableTlsRelay();

		this->tcpState.ackNumber = packetSequenceNumber + 1;
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<std::mt19937::result_type> distrib(1, std::numeric_limits<uint32_t>::max());
		this->tcpState.seqNumber = distrib(gen);

		setTcpStatus(TcpStatus::SYN_RECEIVED);

		const auto windowScaleOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Window);
		if (!windowScaleOpt.isNull()) {
			this->tcpState.windowSizeMultiplier = 1 << windowScaleOpt.getValueAs<uint8_t>();
		}

		const auto mssOpt = tcpLayer->getTcpOption(pcpp::TcpOptionEnumType::Mss);
		if (!mssOpt.isNull()) {
			this->maxSegmentSize = pcpp::netToHost16(mssOpt.getValueAs<uint16_t>());
		}
		this->tcpState.remoteWindowSize = pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) * this->tcpState.windowSizeMultiplier;

		co_await openSocket();

		co_return;
	}

	this->tcpState.remoteWindowSize = pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) * this->tcpState.windowSizeMultiplier;

	if (tcpLayer->getTcpHeader()->ackFlag == 1) {
		auto packetAckNumber = pcpp::netToHost32(tcpLayer->getTcpHeader()->ackNumber);
		this->tcpState.lastRemoteAckedNum = std::max(packetAckNumber, this->tcpState.lastRemoteAckedNum);
		const long long unAcked = static_cast<long long>(this->tcpState.seqNumber) - static_cast<long long>(this->tcpState.lastRemoteAckedNum);
		this->tcpState.unAckedBytes = std::max(unAcked, 0LL);
		if (tcpStatus == TcpStatus::SYN_RECEIVED) {
			setTcpStatus(TcpStatus::ESTABLISHED);
		} else if (tcpStatus == TcpStatus::FIN_WAIT_1 && this->tcpState.lastRemoteAckedNum > this->tcpState.finSeqNumber) {
			setTcpStatus(TcpStatus::FIN_WAIT_2);
		} else if (tcpStatus == TcpStatus::CLOSE_WAIT && this->tcpState.lastRemoteAckedNum > this->tcpState.finSeqNumber) {
			setTcpStatus(TcpStatus::CLOSED);
			closeSocketSoft();
		}
	}

	if (packetSequenceNumber != this->tcpState.ackNumber) {
		// packet is out of order
		if (tcpLayer->getTcpHeader()->rstFlag == 1) {
			closeAllForce();

			co_return;
		}

		log(
			std::format(
				"Received unexpected packet, this packet seq={}, expected={}",
				packetSequenceNumber,
				this->tcpState.ackNumber
			)
		);
		sendAck();

		co_return;
	}

	const size_t dataSize = tcpLayer->getLayerPayloadSize();

	this->tcpState.ackNumber = packetSequenceNumber + dataSize;

	if (dataSize > 0) {
		const auto *dataPtr = tcpLayer->getLayerPayload();

		sendAck();

		const std::span<const uint8_t> span = std::span(dataPtr, dataSize);

		ProcessorRuntimeContext context{
			.connection = shared_from_this(),
			.origPacket = networkLayer,
			.ioContext = proxyService->getIoContext(),
		};
		std::function<std::vector<uint8_t>(size_t, std::span<const uint8_t>)> procChain
			=	[this, &procChain, &context] (size_t i, std::span<const uint8_t> data) -> std::vector<uint8_t> {
				if (i >= processors.size()) {
					return { data.begin(), data.end() };
				}

				return processors[i]->processDataToSocket(
					data,
					context,
					[i, &procChain] (std::span<const uint8_t> d) {
						return procChain(i + 1, d);
					});
			};

		auto out = procChain(0, span);
		if (out.empty()) {
			co_return;
		}
		co_await sendDataToRemote(std::span(out));
	}

	if (tcpLayer->getTcpHeader()->rstFlag == 1) {
		closeAllForce();

		co_return;
	}

	if (tcpLayer->getTcpHeader()->finFlag == 1) {
		if (tcpStatus == TcpStatus::FIN_WAIT_2) {
			this->tcpState.ackNumber += 1;
			sendAck();

			setTcpStatus(TcpStatus::CLOSED);
			closeSocketSoft();

			co_return;
		} else if (tcpStatus == TcpStatus::ESTABLISHED) {
			log("Remote side is initiating TCP close");
			if (this->tcpState.unAckedBytes > 0) {
				this->tcpState.ackNumber += 1;
				sendAck();
				this->tcpState.waitingAck = true;
			} else {
				this->tcpState.ackNumber += 1;
				sendFinAck();
				this->tcpState.finSeqNumber = this->tcpState.seqNumber;
				this->tcpState.seqNumber += 1;
				setTcpStatus(TcpStatus::CLOSE_WAIT);
			}

			co_return;
		}
	}

	if (
		tcpLayer->getTcpHeader()->ackFlag == 1
		&& this->tcpState.unAckedBytes != 0
		&& this->tcpState.waitingAck
		&& tcpStatus != TcpStatus::FIN_WAIT_1
		&& tcpStatus != TcpStatus::FIN_WAIT_2
		&& tcpStatus != TcpStatus::CLOSE_WAIT
	) {
		sendFinAck();
		setTcpStatus(TcpStatus::FIN_WAIT_1);
		this->tcpState.finSeqNumber = this->tcpState.seqNumber;
		this->tcpState.seqNumber += 1;
	}
}

boost::asio::awaitable<void> TcpConnection::openSocket() {
	ZoneScoped;
	if (remoteSocketStatus != RemoteSocketStatus::CLOSED) {
		co_return;
	}

	try {
		setRemoteSocketStatus(RemoteSocketStatus::INITIATING);
		co_await this->destSocket.async_connect(
			boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(this->dstIp.toString()), this->dstPort),
			boost::asio::use_awaitable
		);
		Logger::get().log("Connected to remote socket");
		setRemoteSocketStatus(RemoteSocketStatus::ESTABLISHED);
		sendSynAck();
		this->tcpState.seqNumber += 1;
		connStartTime = std::chrono::system_clock::now();

		boost::asio::co_spawn(
			this->proxyService->getIoContext(),
			[this, ptr = shared_from_this()] -> boost::asio::awaitable<void> {
				co_await this->readLoop();
			},
			boost::asio::detached
		);
	} catch (const boost::system::system_error& err) {
		log(std::format("Failed to connect: {}", err.what()));
		sendRst(true);
		closeSocketSoft();
		setTcpStatus(TcpStatus::CLOSED);

		co_return;
	}
}

void TcpConnection::sendAck() {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto *tcpLayer = buildTcpLayer().release();
	tcpLayer->getTcpHeader()->ackFlag = 1;

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDevice(packet);
}

boost::asio::awaitable<void> TcpConnection::sendDataToRemote(std::span<const uint8_t> data) {
	ZoneScoped;

	this->remoteWriteQueue.emplace_back(data.begin(), data.end());
	if (this->remoteWriteInProgress.exchange(true)) {
		co_return;
	}

	const Defer def([this] {
			this->remoteWriteInProgress = false;
		});

	while (!remoteWriteQueue.empty()) {
		std::vector<uint8_t> nextChunk = std::move(remoteWriteQueue.front());
		remoteWriteQueue.pop_front();

		try {
			const auto len = co_await boost::asio::async_write(
				this->destSocket,
				boost::asio::buffer(nextChunk),
				boost::asio::use_awaitable
			);
			sentBytes += len;
		} catch (...) {
			break;
		}
	}
}

boost::asio::awaitable<void> TcpConnection::read() {
	ZoneScoped;

	std::vector<uint8_t> buffer(16 * 1024);

	unsigned long long length;
	try {
		length = co_await this->destSocket.async_read_some(boost::asio::buffer(buffer), boost::asio::use_awaitable);
	} catch (const boost::system::system_error& err) {
		if (err.code() != boost::asio::error::eof) {
			log(std::format("read failed: {}", err.what()));
			sendRst(true);
			setTcpStatus(TcpStatus::CLOSED);
			closeSocketSoft();

			throw;
		}

		// socket closed
		closeSocketSoft();
		if (
			tcpStatus == TcpStatus::FIN_WAIT_1
			|| tcpStatus == TcpStatus::FIN_WAIT_2 || tcpStatus == TcpStatus::CLOSE_WAIT || this->tcpState.waitingAck
		) {
			throw;
		}

		if (this->tcpState.unAckedBytes > 0) {
			log("Waiting for ack on everything before closing connection");
			this->tcpState.waitingAck = true;
		} else {
			log("We are initiating TCP close");
			sendFinAck();
			setTcpStatus(TcpStatus::FIN_WAIT_1);
			this->tcpState.finSeqNumber = this->tcpState.seqNumber;
			this->tcpState.seqNumber += 1;
		}

		throw;
	}

	receivedBytes += length;

	ProcessorRuntimeContext context{
		.connection = shared_from_this(),
		.origPacket = nullptr,
		.ioContext = proxyService->getIoContext(),
	};
	std::function<std::vector<uint8_t>(size_t, std::span<const uint8_t>)> procChain
		=	[this, &procChain, &context] (size_t i, std::span<const uint8_t> data) -> std::vector<uint8_t> {
			if (i >= processors.size()) {
				return { data.begin(), data.end() };
			}

			return processors[i]->processDataToDevice(
				data,
				context,
				[i, &procChain] (std::span<const uint8_t> d) {
					return procChain(i + 1, d);
				});
		};

	auto out = procChain(0, std::span(buffer.begin(), length));
	if (out.empty()) {
		co_return;
	}
	sendDataToDevice(std::span(out));
}

boost::asio::awaitable<void> TcpConnection::readLoop() {
	try {
		while (this->destSocket.is_open()) {
			co_await this->read();
		}
	} catch (...) {}
	log("readLoop exited");
}

std::unique_ptr<pcpp::Packet> TcpConnection::encapsulateResponseDataToPacket(std::span<const uint8_t> data) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto *tcpLayer = buildTcpLayer().release();
	tcpLayer->getTcpHeader()->ackFlag = 1;
	tcpLayer->getTcpHeader()->pshFlag = 1;
	auto *payloadLayer = new pcpp::PayloadLayer(data.data(), data.size());

	auto tcpPacket = std::make_unique<pcpp::Packet>(data.size() + 100);
	tcpPacket->addLayer(ipLayer, true);
	tcpPacket->addLayer(tcpLayer, true);
	tcpPacket->addLayer(payloadLayer, true);

	tcpPacket->computeCalculateFields();

	return tcpPacket;
}

void TcpConnection::sendDataToDevice(std::span<const uint8_t> data) {
	ZoneScoped;

	size_t offset = 0;
	const unsigned int maxSegmentSize = std::min(this->maxSegmentSize, DEFAULT_MAX_SEGMENT_SIZE);
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

		sendToDevice(*packet);

		this->tcpState.seqNumber += length;
		this->tcpState.unAckedBytes += length;
		offset += length;
	}
}

void TcpConnection::sendRst(bool ack) {
	pcpp::Layer *ipLayer = buildIpLayer().release();

	auto *tcpLayer = buildTcpLayer().release();
	tcpLayer->getTcpHeader()->rstFlag = 1;
	if (ack) {
		tcpLayer->getTcpHeader()->ackFlag = 1;
	}

	pcpp::Packet packet(80);
	packet.addLayer(ipLayer, true);
	packet.addLayer(tcpLayer, true);

	packet.computeCalculateFields();

	sendToDevice(packet);
}

TcpStatus TcpConnection::getTcpStatus() const {
	return this->tcpStatus;
}

void TcpConnection::setTcpStatus(TcpStatus tcpStatus) {
	if (this->tcpStatus == tcpStatus) {
		return;
	}
	auto old = this->tcpStatus;
	this->tcpStatus = tcpStatus;
	log(std::format("TCP status changed from {} to {}", tcpStatusToString(old), tcpStatusToString(tcpStatus)));

	RemoteSocketStatus oldMapped = tcpStatusToRemoteSocketStatus(old);
	RemoteSocketStatus newMapped = tcpStatusToRemoteSocketStatus(tcpStatus);
	std::ranges::for_each(this->processors, [&](auto& p) { p->onClientConnectionChanged(oldMapped, newMapped); });
}

void TcpConnection::closeAllForce() {
	if (this->remoteSocketStatus != RemoteSocketStatus::CLOSED) {
		setRemoteSocketStatus(RemoteSocketStatus::CLOSED);
	}
	if (this->tcpStatus != TcpStatus::CLOSED) {
		sendRst(true);
	}

	try {
		this->destSocket.close();
	} catch (...) {}
	setTcpStatus(TcpStatus::CLOSED);
	logToFile();
}

bool TcpConnection::canRemove() const {
	return tcpStatus == TcpStatus::CLOSED && remoteSocketStatus == RemoteSocketStatus::CLOSED;
}

void TcpConnection::logToFile() {
	if (tcpStatus != TcpStatus::CLOSED || remoteSocketStatus != RemoteSocketStatus::CLOSED) {
		return;
	}
	Connection::logToFile();
}

std::unique_ptr<pcpp::TcpLayer> TcpConnection::buildTcpLayer() const {
	auto tcpLayer = std::make_unique<pcpp::TcpLayer>(dstPort, srcPort);
	tcpLayer->getTcpHeader()->ackNumber = pcpp::hostToNet32(this->tcpState.ackNumber);
	tcpLayer->getTcpHeader()->sequenceNumber = pcpp::hostToNet32(this->tcpState.seqNumber);
	tcpLayer->getTcpHeader()->windowSize = pcpp::hostToNet16(this->tcpState.ourWindowSize);

	return tcpLayer;
}
