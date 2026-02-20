
#ifndef ZT_CERTIFICATE_H
#define ZT_CERTIFICATE_H

#include <string>
#include <ctime>
#include <unordered_set>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>

/**
 * \class CertificateAuthority
 * \brief Simulates a Certificate Authority (CA) that issues and signs identity certificates.
 *
 * The CA generates a public-private RSA key pair and uses it to sign certificates
 * for nodes, which include identity, role, and expiry information.
 */
class CertificateAuthority {
public:
  /**
   * \brief Constructor that initializes and generates RSA key pair.
   */
  CertificateAuthority();

  /**
   * \brief Signs an identity certificate with node ID, role, and expiry.
   * \param nodeId The unique identifier of the node.
   * \param role The assigned role of the node (e.g., "sensor", "gateway").
   * \param expiry Expiry timestamp for the certificate.
   * \return A signed certificate string in plain format with a base64-encoded signature.
   */
  std::string SignIdentity(uint32_t nodeId, const std::string& role, time_t expiry);

  /**
   * \brief Retrieves the public RSA key of the CA.
   * \return The public key corresponding to the CA's private key.
   */
  CryptoPP::RSA::PublicKey GetPublicKey() const;

private:
  CryptoPP::RSA::PrivateKey privateKey; ///< RSA private key used for signing certificates.
  CryptoPP::RSA::PublicKey publicKey;   ///< RSA public key distributed for verification.
};

/**
 * \class ZtPolicyEngineWithCert
 * \brief Simulates a Zero Trust policy engine that enforces access control using certificates.
 *
 * This engine validates node certificates, verifies digital signatures, checks role and expiry,
 * and maintains a list of revoked node IDs.
 */
class ZtPolicyEngineWithCert {
public:
  /**
   * \brief Sets the CA's public key used for certificate verification.
   * \param pub The public RSA key of the trusted Certificate Authority.
   */
  void SetCaPublicKey(CryptoPP::RSA::PublicKey pub);

  /**
   * \brief Revokes a node by its ID, preventing it from being authorized.
   * \param nodeId The node ID to be added to the revocation list.
   */
  void Revoke(uint32_t nodeId);

  /**
   * \brief Authorizes a node based on its certificate.
   * \param nodeId The node's claimed ID.
   * \param role The role the node claims to perform.
   * \param certStr The certificate string presented by the node.
   * \return True if the certificate is valid, not expired, matches the node, and not revoked.
   */
  bool Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr);

private:
  CryptoPP::RSA::PublicKey caPublicKey; ///< Trusted public key used for signature verification.
  std::unordered_set<uint32_t> revoke;  ///< Set of node IDs that are explicitly revoked.
};

#endif // ZT_CERTIFICATE_H

