

#ifndef ZT_TLS_HANDSHAKE_H
#define ZT_TLS_HANDSHAKE_H

#include "ns3/object.h"
#include "ns3/node.h"
#include <map>
#include <string>
#include <functional>

namespace ns3 {

/**
 * \ingroup zerotrust
 * \class ZtTlsHandshake
 * \brief Simulates a Zero Trust-based TLS handshake mechanism between NS-3 nodes.
 *
 * This class is responsible for performing identity-validated TLS-like handshakes
 * between IoT nodes, establishing symmetric session keys, and enforcing policy-based
 * authentication using injected policy validation logic.
 */
class ZtTlsHandshake : public Object {
public:
  /**
   * \brief Get the NS-3 TypeId.
   * \return TypeId of the ZtTlsHandshake class.
   */
  static TypeId GetTypeId();

  /**
   * \brief Constructor.
   */
  ZtTlsHandshake();

  /**
   * \brief Start a simulated TLS handshake between client and server nodes.
   *
   * Performs mutual policy validation and generates a symmetric session key
   * shared by both nodes.
   *
   * \param client Pointer to the client node.
   * \param server Pointer to the server node.
   * \param clientId Unique identifier for the client node.
   * \param serverId Unique identifier for the server node.
   */
  void StartHandshake(Ptr<Node> client, Ptr<Node> server, uint32_t clientId, uint32_t serverId);

  /**
   * \brief Check if a session exists for a given peer.
   * \param peerId Node ID of the peer.
   * \return true if a session exists, false otherwise.
   */
  bool HasSession(uint32_t peerId) const;

  /**
   * \brief Retrieve the session key for a peer in hexadecimal string format.
   * \param peerId Node ID of the peer.
   * \return Hex-encoded session key if it exists, empty string otherwise.
   */
  std::string GetSessionKey(uint32_t peerId) const;

  /**
   * \brief Set an external logger for emitting TLS logs.
   * \param logger Function accepting a string message.
   */
  void SetExternalLogger(std::function<void(std::string)> logger);

  /**
   * \brief Set a policy validator for enforcing Zero Trust identity checks.
   * \param validator Function taking node ID and role string, returns true if authorized.
   */
  void SetPolicyValidator(std::function<bool(uint32_t, std::string)> validator);

private:
  /**
   * \brief Emit a log message using the external logger or NS_LOG fallback.
   * \param msg The message to log.
   */
  void Log(const std::string& msg) const;

  std::map<uint32_t, std::string> m_sessionKeys;               //!< Maps node IDs to session keys.
  std::function<void(std::string)> m_logger;                   //!< Optional external logger.
  std::function<bool(uint32_t, std::string)> m_policyValidator; //!< Optional external policy validator.
};

} // namespace ns3

#endif // ZT_TLS_HANDSHAKE_H

