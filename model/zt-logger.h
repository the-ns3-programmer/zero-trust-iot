
#ifndef ZT_LOGGER_H
#define ZT_LOGGER_H

#include <string>
#include <ctime>
#include <cstdint>

/**
 * \class ZtLogger
 * \brief Logging utility for Zero Trust simulation modules in NS-3.
 *
 * Provides logging functions for general events, certificate-related events,
 * and encryption/decryption actions. Supports optional timestamps.
 */
class ZtLogger {
public:
  /**
   * \brief Enables or disables timestamp logging.
   * \param enable True to include timestamps in logs, false to omit them.
   */
  static void EnableTimestamps(bool enable);

  /**
   * \brief Logs a general message with a specified tag.
   * \param tag Context label (e.g., "INFO", "ERROR").
   * \param message The message content.
   */
  static void Log(const std::string &tag, const std::string &message);

  /**
   * \brief Logs a certificate issuance event.
   * \param nodeId ID of the node receiving the certificate.
   * \param role Assigned role for the node.
   * \param expiry Expiry time of the certificate.
   */
  static void LogCertIssued(uint32_t nodeId, const std::string &role, time_t expiry);

  /**
   * \brief Logs the result of certificate validation.
   * \param nodeId ID of the node whose certificate was validated.
   * \param valid True if the certificate is valid, false otherwise.
   */
  static void LogCertValidationResult(uint32_t nodeId, bool valid);

  /**
   * \brief Logs a certificate revocation event.
   * \param nodeId ID of the node whose certificate was revoked.
   */
  static void LogCertRevoked(uint32_t nodeId);

  /**
   * \brief Logs a rejected certificate attempt with a reason.
   * \param reason Description of the rejection cause.
   */
  static void LogCertRejected(const std::string &reason);

  /**
   * \brief Logs an encryption event with payload and IV.
   * \param payload The encrypted data.
   * \param ivHex Initialization Vector in hex string format.
   */
  static void LogEncryption(const std::string &payload, const std::string &ivHex);

  /**
   * \brief Logs a successful decryption event.
   * \param payload The decrypted plaintext data.
   */
  static void LogDecryption(const std::string &payload);

  /**
   * \brief Logs a decryption failure event.
   */
  static void LogDecryptionFailure();

private:
  static bool timestampsEnabled; ///< Flag to indicate if timestamps are enabled in logs.
};

#endif // ZT_LOGGER_H

