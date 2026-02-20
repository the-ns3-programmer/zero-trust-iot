
#include "zt-logger.h"
#include <ns3/core-module.h>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace ns3;

/// Static flag to control timestamp display
bool ZtLogger::timestampsEnabled = true;

/**
 * \brief Enables or disables timestamps in log messages.
 * \param enable If true, timestamps will be included in logs.
 */
void ZtLogger::EnableTimestamps(bool enable) {
  timestampsEnabled = enable;
}

/**
 * \brief Logs a message with a given tag and optional timestamp.
 * \param tag A short string indicating the type or source of the message.
 * \param message The actual log message content.
 */
void ZtLogger::Log(const std::string &tag, const std::string &message) {
  std::ostringstream output;

  if (timestampsEnabled) {
    std::time_t now = std::time(nullptr);
    std::tm *lt = std::localtime(&now);
    output << "[" << std::put_time(lt, "%H:%M:%S") << "] ";
  }

  output << "[" << tag << "] " << message;
  NS_LOG_UNCOND(output.str());
}

// === Certificate Logs ===

/**
 * \brief Logs the issuance of a certificate.
 * \param nodeId The ID of the node receiving the certificate.
 * \param role The assigned role in the certificate.
 * \param expiry The expiration time of the certificate.
 */
void ZtLogger::LogCertIssued(uint32_t nodeId, const std::string &role, time_t expiry) {
  std::ostringstream msg;
  msg << "Issued certificate to Node " << nodeId << " | Role: " << role
      << " | Expiry: " << expiry;
  Log("ZT-CERT", msg.str());
}

/**
 * \brief Logs the result of a certificate validation attempt.
 * \param nodeId The node whose certificate was validated.
 * \param valid True if the certificate is valid, false otherwise.
 */
void ZtLogger::LogCertValidationResult(uint32_t nodeId, bool valid) {
  Log("ZT-CERT", "Validation for Node " + std::to_string(nodeId) +
      (valid ? ": VALID" : ": INVALID"));
}

/**
 * \brief Logs the revocation of a certificate.
 * \param nodeId The ID of the node whose certificate was revoked.
 */
void ZtLogger::LogCertRevoked(uint32_t nodeId) {
  Log("ZT-CERT", "Node " + std::to_string(nodeId) + " certificate revoked");
}

/**
 * \brief Logs a rejection reason for a certificate.
 * \param reason The explanation for why the certificate was rejected.
 */
void ZtLogger::LogCertRejected(const std::string &reason) {
  Log("ZT-CERT", "Certificate rejected: " + reason);
}

// === Encryption Logs ===

/**
 * \brief Logs encryption activity with IV and encrypted data.
 * \param payload The encrypted data in hex or readable format.
 * \param ivHex The IV used during encryption, in hex format.
 */
void ZtLogger::LogEncryption(const std::string &payload, const std::string &ivHex) {
  Log("ZT-ENC", "Payload encrypted | IV: " + ivHex + " | Data: " + payload);
}

/**
 * \brief Logs a successful decryption result.
 * \param payload The decrypted plaintext.
 */
void ZtLogger::LogDecryption(const std::string &payload) {
  Log("ZT-DEC", "Decrypted Payload: " + payload);
}

/**
 * \brief Logs a failure during decryption due to invalid session or corrupted data.
 */
void ZtLogger::LogDecryptionFailure() {
  Log("ZT-DEC", "Decryption failed: Invalid session or corrupt data");
}

