
#include "X509CRL.h"
#include <cassert>

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/pem.h>

#include "../openssl/Globals.h"
#include "../Exception.h"
#include "../NullPointerException.h"
#include "../InvalidArgumentException.h"
#include "../utils/ByteArray.h"
#include "../utils/DateTime.h"
#include "../utils/File.h"
#include "../utils/BigInteger.h"
#include "../asn1/ObjectID.h"
#include "../asn1/DistinguishedName.h"
#include "../asn1/AlgorithmID.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "X509Extension.h"
#include "X509Certificate.h"
#include "X509CRLEntry.h"
#include "extensions/CRLNumber.h"
#include "extensions/DeltaCRLIndicator.h"
#include "extensions/IssuerAltName.h"

using namespace std;

namespace PKIBox
{
	namespace x509
	{
		//---------------------------------------------------------------------------------------
		// Function name	: X509CRL()
		// Description	    : Default constructor. Initializes m_pCRL to NULL.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		X509CRL::X509CRL() : m_pCRL(NULL)
		{
		}


		//---------------------------------------------------------------------------------------
		// Function name	: MakeDER()
		// Description	    : Checks whether the CRL bytes are in DER or PEM. If CRL's bytes are in
		//                    PEM then it converts them to DER and returns. If CRL's bytes are in DER,
		//					  it simply return SECSuccess.
		// Return type		: SECStatus
		//						SECSuccess if all steps are successful otherwise SECFaliure.
		// Argument         : SECItem *SecItem
		//                          pointer to SecItem containing CRL's bytes
		//---------------------------------------------------------------------------------------
		bool X509CRL::IsDER(const unsigned char *pbArray)
		{
			assert(pbArray != NULL);
			return pbArray[0] == '0' ? true : false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: Construct()
		// Description	    : A private utility method to create a X509CRL form a PEM or
		//                    DER byte array. This method is called from several different constructors.
		//                    It is used to reduce code duplication. First it makes the CRL 
		//                    bytes to DER as NSS only deals in DER encoded ASN.1 data structures.
		//                    Then calls NSS to create a CRL and assign it to m_pCRL;
		// Return type		: Nothing
		// Argument         : unsigned char *pbArray
		//						Buffer containing CRL bytes.
		//					  unsigned int cLength
		//						Size of the buffer.
		//---------------------------------------------------------------------------------------
		void X509CRL::Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (Exception) */
		{
			assert(pbArray != NULL);
			assert(cLength > 0);

			if(IsDER(pbArray)) // DER
			{
				m_pCRL = ::d2i_X509_CRL(&m_pCRL, &pbArray, cLength);
				if(!m_pCRL)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
				pbArray -= cLength;
			}
			else // PEM
			{
				BIO *pBIO = ::BIO_new(BIO_s_mem());
				if(!pBIO)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int iRet = ::BIO_write(pBIO, pbArray, cLength);

				m_pCRL = PEM_read_bio_X509_CRL(pBIO, NULL, NULL, NULL);
				if(!m_pCRL)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					iRet = ::BIO_free(pBIO);
					throw Exception(pc);
				}

				iRet = ::BIO_free(pBIO);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: X509CRL()
		// Description	    : Two argument constructor. Constructs a CRL from PEM/DER bytes contained
		//                    in a buffer.
		// Argument         : unsigned char *pbArray
		//						Buffer containing CRL bytes.
		//					  unsigned int cLength
		//						Size of the buffer.
		//---------------------------------------------------------------------------------------
		X509CRL::X509CRL(/*const */unsigned char *pbArray, unsigned int cLength) : m_pCRL(NULL) /* throw (Exception) */
		{
			Construct(pbArray, cLength);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: X509CRL()
		// Description	    : Constructs a CRL object from a file on disk. Loads a file 
		//                    from disk using NSS and then calls Construct() for construction.
		// Return type		: Nothing
		// Argument         : const char *szFileName
		//						Name of the CRL file on disk
		//---------------------------------------------------------------------------------------
		X509CRL::X509CRL(const char *szFileName) : m_pCRL(NULL) /* throw (Exception)*/
		{
			assert(szFileName != NULL);

			utils::ByteArray baCRL = utils::File::Load(szFileName);
			if(baCRL.IsEmpty())
			{
				throw Exception("The specified file is empty.");
			}

			unsigned char *puc = const_cast<unsigned char *>( baCRL.GetData() );
			unsigned int uiSize = baCRL.GetLength();

			Construct(puc, uiSize);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: X509CRL()
		// Description	    : Constructs a CRL object from a ByteArray. Delegates call to 
		//                    member function Construct().
		// Return type		: Nothing
		// Argument         : CByteArray &ByteArray
		//						ByteArray containing CRL bytes.
		//---------------------------------------------------------------------------------------
		X509CRL::X509CRL(const utils::ByteArray &ByteArray)  : m_pCRL(NULL) /* throw (Exception) */
		{
			Construct(const_cast<unsigned char *>(ByteArray.GetData()), ByteArray.GetLength());
		}


		//---------------------------------------------------------------------------------------
		// Function name	: ~X509CRL()
		// Description	    : Destructor. Decrements the reference counter and destroys CRL 
		//                    accordingly.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		X509CRL::~X509CRL()
		{
			if(m_pCRL)
			{
				::X509_CRL_free(m_pCRL);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: X509CRL()
		// Description	    : Copy constructor.
		// Return type		: Nothing
		// Argument         : const X509CRL &rhs
		//						CRL from which to copy.
		//---------------------------------------------------------------------------------------
		X509CRL::X509CRL(const X509CRL &rhs)
		{
			m_pCRL = X509_CRL_dup(rhs.m_pCRL);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator=()
		// Description	    : Copy assignment.
		// Return type		: X509CRL &
		//						*this
		// Argument         : const X509CRL &rhs
		//						CRL from which to assign.
		//---------------------------------------------------------------------------------------
		X509CRL &X509CRL::operator=(const X509CRL &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if(m_pCRL)
			{
				::X509_CRL_free(m_pCRL);
			}

			// Assign new values
			m_pCRL = X509_CRL_dup(rhs.m_pCRL);

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetEncoded()
		// Description	    : Returns this X509CRL as DER encoded ASN.1 data structure. 
		//                    Constructs a ByteArray from the DER bytes of CRL and returns it.
		// Return type		: auto_ptr<CByteArray>
		//						Smart pointer to ByteArray containing CRL's DER bytes.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::ByteArray X509CRL::GetEncoded() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get in encoded form.");

			utils::ByteArray ba;
			int iSize = ::i2d_X509_CRL(m_pCRL, NULL);
			if(iSize == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
			iSize = ::i2d_X509_CRL(m_pCRL, &pEncoded);
			pEncoded -= iSize;

			ba.Set(pEncoded, iSize);

			::free(pEncoded);  // Deallocate

			return ba;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetVersion()
		// Description	    : Returns version of a CRL. NSS gives 0 for version 1, 1 for 
		//                    version 2 and so on so this method increments version internally i.e.
		//                    it returns 1 for V1 CRLs, 2 for V2 CRLs and so on.
		// Return type		: int
		//						version of a CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int X509CRL::GetVersion() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get version from.");

			return (::ASN1_INTEGER_get(m_pCRL->crl->version) + 1);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::SetVersion(unsigned int iVersion) /* throw (Exception)*/
		{
			if(!m_pCRL)
			{
				m_pCRL = X509_CRL_new();
				if(!m_pCRL)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);				
				}
			}

			int iRet = X509_CRL_set_version(m_pCRL, iVersion);
			if(iRet == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: GetThisUpdate()
		// Description	    : Returns ThisUpdate field of a CRL.
		// Return type		: CDate 
		//						ThisUpdate date of a CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::DateTime X509CRL::GetThisUpdate() const /* throw (Exception) */
		{
			if(!m_pCRL)
			{
				throw NullPointerException("There is no CRL to get ThisUpdate from.");
			}

			time_t Time = ::ASN1_UTCTIME_get(m_pCRL->crl->lastUpdate);
			return utils::DateTime(Time);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::SetThisUpdate(const utils::DateTime &thisUpdate)
		{
			if(!m_pCRL)
			{
				m_pCRL = ::X509_CRL_new();
			}

			ASN1_TIME *lastUpdate = ::ASN1_TIME_set(NULL, thisUpdate.GetTime());
			if(!lastUpdate)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			int iRet = ::X509_CRL_set_lastUpdate(m_pCRL, lastUpdate);
			if( -1 == iRet )
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(lastUpdate)
					::ASN1_TIME_free(lastUpdate);

				throw Exception(pc);
			}

			if(lastUpdate)
				::ASN1_TIME_free(lastUpdate);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetMextUpdate()
		// Description	    : Returns NextUpdate field of a CRL.
		// Return type		: CDate 
		//						NextUpdate date of a CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::DateTime X509CRL::GetNextUpdate() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get NextUpdate from.");

			time_t Time = ::ASN1_UTCTIME_get(m_pCRL->crl->nextUpdate);
			return utils::DateTime(Time);


		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::SetNextUpdate(const utils::DateTime &nextUpdate)
		{
			if(!m_pCRL)
			{
				m_pCRL = X509_CRL_new();
			}

			ASN1_TIME *pNextUpdate = ::ASN1_TIME_set(NULL, nextUpdate.GetTime());
			if(!pNextUpdate)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			int iRet = X509_CRL_set_nextUpdate(m_pCRL, pNextUpdate);
			if( -1 == iRet )
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pNextUpdate)
					::ASN1_TIME_free(pNextUpdate);

				throw Exception(pc);
			}

			if(pNextUpdate)
				::ASN1_TIME_free(pNextUpdate);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetIssuerDN()
		// Description	    : Returns issuer DN of CRL as string.
		// Return type		: string
		//						Issuer DN of CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		asn1::DistinguishedName X509CRL::GetIssuerDN() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get Issuer DN from.");

			asn1::DistinguishedName DN;
			DN.m_pX509Name = ::X509_NAME_dup(m_pCRL->crl->issuer);
			return DN;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: GetIssuerDN()
		// Description	    : Returns issuer DN of CRL as string.
		// Return type		: string
		//						Issuer DN of CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		void X509CRL::SetIssuerDN(const asn1::DistinguishedName &issuer)
		{
			if(!m_pCRL)
			{
				m_pCRL = ::X509_CRL_new();
			}

			int iRet = X509_CRL_set_issuer_name(m_pCRL, issuer.m_pX509Name);
			if( -1 == iRet )
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: GetSigAlgName()
		// Description	    : Returns the algorithm name of the signature as string.
		// Return type		: string
		//						Algorithm name of signature algorithm.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		std::auto_ptr<asn1::AlgorithmID> X509CRL::GetSignatureAlgorithm() const /* throw (CExceptoin) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get Signature Algorithm from.");

			if(m_pCRL->sig_alg)
			{
				std::auto_ptr<asn1::AlgorithmID> pSigAlgorithm( new asn1::AlgorithmID);
				pSigAlgorithm->m_pAlgID = X509_ALGOR_dup(m_pCRL->sig_alg);
				return pSigAlgorithm;
			}

			return std::auto_ptr<asn1::AlgorithmID>(NULL);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetSignature()
		// Description	    : Returns signature of this CRL as ByteAray. This method returns
		//                    the raw signature bytes as ByteArray.
		// Return type		: auto_ptr<CByteArray>
		//						Smart pointer to CByteArray containing raw signature bytes.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::ByteArray X509CRL::GetSignature() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get Signature from.");

			utils::ByteArray ba;

			int iSize = ::i2d_ASN1_BIT_STRING(m_pCRL->signature, NULL);
			if(iSize == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
			iSize = ::i2d_ASN1_BIT_STRING(m_pCRL->signature, &pEncoded);
			pEncoded -= iSize;

			ba.Set(pEncoded, iSize);

			::free(pEncoded);  // Deallocate

			return ba;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::IsRevoked(const utils::BigInteger &serialNumber)
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to check revoked certificates from.");

			if(!m_pCRL->crl->revoked)
				return false;

			unsigned int cEntries = sk_X509_REVOKED_num(m_pCRL->crl->revoked);
			if( 0 == cEntries)
				return false;

			ASN1_INTEGER *pSerialNumber = BN_to_ASN1_INTEGER(serialNumber.m_pBN, NULL);
			if(!pSerialNumber)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			for(unsigned int i=0; i<cEntries; ++i)
			{
				X509_REVOKED *pCRLEntry = (X509_REVOKED *)sk_X509_REVOKED_value(m_pCRL->crl->revoked, i);
				if( 0 == ASN1_INTEGER_cmp(pCRLEntry->serialNumber, pSerialNumber) )
				{
					if(pSerialNumber)
						ASN1_INTEGER_free(pSerialNumber);
					return true;
				}
			}

			if(pSerialNumber)
				ASN1_INTEGER_free(pSerialNumber);

			return false;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::IsRevoked(const X509Certificate &cert)
		{
			return IsRevoked(cert.GetSerialNumber());
		}

		//---------------------------------------------------------------------------------------
		// Function name	: GetRevokedCertificates()
		// Description	    : Returns Revoked certificates present in this CRL. This method iterates
		//                    over NSS array of revoked certificate entries, construct a X509CRLEntry
		//                    from each revoked entry and add it to the vector. In the end this method
		//                    returns this vector to the caller.
		// Return type		: auto_ptr< vector<X509CRLEntry> >
		//						Smart pointer to the vector of CRL entries.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		std::vector<X509CRLEntry> X509CRL::GetRevokedCertificates() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get revoked certificates from.");

			vector<X509CRLEntry> vCRLEntries;
			if(m_pCRL->crl->revoked)
			{
				unsigned int cEntries = sk_X509_REVOKED_num(m_pCRL->crl->revoked);
				for(unsigned int i=0; i<cEntries; ++i)
				{
					X509_REVOKED *pCRLEntry = (X509_REVOKED *)sk_X509_REVOKED_value(m_pCRL->crl->revoked, i);

					X509CRLEntry crlEntry;
					crlEntry.m_pCRLEntry = X509_REVOKED_dup(pCRLEntry); 

					vCRLEntries.push_back(crlEntry);
				}
			}

			return vCRLEntries;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::SetRevokedCertificates(const std::vector<X509CRLEntry> &revokedCerts) /* throw (Exception) */
		{
			if(!m_pCRL)
			{
				m_pCRL = X509_CRL_new();
				if(!m_pCRL)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			STACK_OF(X509_REVOKED) *revoked = sk_X509_REVOKED_new_null();
			for(unsigned int i=0; i<revokedCerts.size(); ++i)
			{
				sk_X509_REVOKED_push(revoked, X509_REVOKED_dup(revokedCerts[i].m_pCRLEntry) );
			}

			if(m_pCRL->crl->revoked)
			{
				sk_X509_REVOKED_pop_free(m_pCRL->crl->revoked, X509_REVOKED_free);
				m_pCRL->crl->revoked = NULL;
			}

			m_pCRL->crl->revoked = revoked;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetRevokedCertificate()
		// Description	    : Returns a revoked entry according to the serial number provided.
		// Return type		: auto_ptr<X509CRLEntry>
		//						Smart pointer to the CRL entry.
		// Argument         : const string &sSerialNumber
		//						Serial number according to which we have to find revoked entry 
		//---------------------------------------------------------------------------------------
		std::auto_ptr<X509CRLEntry> X509CRL::GetRevokedCertificate(const utils::BigInteger &serialNumber) const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get revoked certificate from.");

			if(m_pCRL->crl->revoked)
			{
				unsigned int cEntries = sk_X509_REVOKED_num(m_pCRL->crl->revoked);

				ASN1_INTEGER *pSerialNumber = BN_to_ASN1_INTEGER(serialNumber.m_pBN, NULL);
				if(!pSerialNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				for(unsigned int i=0; i<cEntries; ++i)
				{
					X509_REVOKED *pCRLEntry = (X509_REVOKED *)sk_X509_REVOKED_value(m_pCRL->crl->revoked, i);

					if( 0 == ASN1_INTEGER_cmp(pCRLEntry->serialNumber, pSerialNumber) )
					{
						if(pSerialNumber)
							ASN1_INTEGER_free(pSerialNumber);

						auto_ptr<X509CRLEntry> p( new X509CRLEntry );
						p->m_pCRLEntry = X509_REVOKED_dup(pCRLEntry); 
						return p;
					}
				}

				if(pSerialNumber)
					ASN1_INTEGER_free(pSerialNumber);
				return auto_ptr<X509CRLEntry>(NULL);
			}

			return auto_ptr<X509CRLEntry>(NULL);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::AddCertificate(const X509CRLEntry &revokedCert)
		{
			if(!m_pCRL)
			{
				m_pCRL = X509_CRL_new();
				if(!m_pCRL)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			int iRet = X509_CRL_add0_revoked(m_pCRL, X509_REVOKED_dup(revokedCert.m_pCRLEntry) );
			if(-1 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::AddCertificate(const x509::X509Certificate &cert, const utils::DateTime &revocationDate)
		{
			AddCertificate(X509CRLEntry(cert, revocationDate));
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::RemoveCertificate(const utils::BigInteger &serialNumber)
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to remove certificate from.");

			if(m_pCRL->crl->revoked)
			{
				unsigned int cEntries = sk_X509_REVOKED_num(m_pCRL->crl->revoked);

				ASN1_INTEGER *pSerialNumber = BN_to_ASN1_INTEGER(serialNumber.m_pBN, NULL);
				if(!pSerialNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				for(unsigned int i=0; i<cEntries; ++i)
				{
					X509_REVOKED *pCRLEntry = (X509_REVOKED *)sk_X509_REVOKED_value(m_pCRL->crl->revoked, i);

					if( 0 == ASN1_INTEGER_cmp(pCRLEntry->serialNumber, pSerialNumber) )
					{
						if(pSerialNumber)
							ASN1_INTEGER_free(pSerialNumber);

						X509_REVOKED_free(pCRLEntry);

						sk_X509_REVOKED_delete(m_pCRL->crl->revoked, i);
						return true;
					}
				}

				if(pSerialNumber)
					ASN1_INTEGER_free(pSerialNumber);
			}

			return false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::RemoveCertificate(const X509Certificate &cert)
		{
			return RemoveCertificate(cert.GetSerialNumber());
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::RemoveAllCertificates()
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to remove certificates from.");

			if(m_pCRL->crl->revoked)
			{
				sk_X509_REVOKED_pop_free(m_pCRL->crl->revoked, X509_REVOKED_free);
				m_pCRL->crl->revoked = NULL;
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::Sign(const PrivateKey &privateKey)
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to sign.");

			int iRet = ::X509_CRL_sign(m_pCRL, privateKey.m_pPrivateKey, EVP_get_digestbyname("sha1"));
			if(iRet == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: Verify()
		// Description	    : Verifies the signature of CRL with the provided public key.
		// Return type		: bool
		//						true if signature is verified successfully otherwise false.
		// Argument         : PublicKey &key
		//						Public Key from which to verify.
		//---------------------------------------------------------------------------------------
		bool X509CRL::Verify(PublicKey &Key) /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to verify.");

			OpenSSL_add_all_algorithms();
			::OpenSSL_add_all_digests();
			::ERR_load_crypto_strings();

			int iRet = ::X509_CRL_verify(m_pCRL, Key.m_pKey);
			if(iRet != 1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			return true;
		}



		//---------------------------------------------------------------------------------------
		// Function name	: Verify()
		// Description	    : Verifies the signature of this CRL object using the public 
		//                    key of the provided certificate.
		// Return type		: bool
		//						true if signature is verified successfully otherwise false.
		// Argument         : const X509Certificate &IssuerCert
		//						Issuer's certificate whose public key will be used  to verify.
		//---------------------------------------------------------------------------------------
		bool X509CRL::Verify(const X509Certificate &IssuerCert) /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to verify.");

			OpenSSL_add_all_algorithms();
			::OpenSSL_add_all_digests();
			::ERR_load_crypto_strings();

			int iRet = ::X509_CRL_verify(m_pCRL, IssuerCert.GetPublicKey().m_pKey);
			if(iRet != 1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			return true;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: HasExtensions()
		// Description	    : Checks whether this CRL has extensions or not?
		// Return type		: bool
		//						true if this CRL has extensions otherwise false.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		bool X509CRL::HasExtensions() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to check extensions for.");

			return m_pCRL->crl->extensions != NULL;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetNumberOfExtensions()
		// Description	    : Returns the total number of extensions present in this CRL. 
		//                    This method iterates over NSS array of extensions and just count the 
		//                    number of iterations. In the end it returns this count.
		// Return type		: unsigned int
		//						Total number of extensions present in this CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		unsigned int X509CRL::GetNumberOfExtensions() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get number of extensions from.");
			
			return ::X509_CRL_get_ext_count(m_pCRL);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetExtensions()
		// Description	    : Returns all the extensions present in this CRL. This method
		//                    iterates over the NSS array of extensions, constructs a X509Extension
		//                    object for each extension, add it to the vector and in the end returns 
		//                    vector to the caller.
		// Return type		: auto_ptr< vector<X509Extension> >
		//						Smart pointer to a vector of extensions.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		std::vector< clone_ptr<x509::X509Extension> > X509CRL::GetExtensions() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get extensions from.");

			vector< clone_ptr<x509::X509Extension> > vExtensions;
			if(m_pCRL->crl->extensions)
			{
				vExtensions.reserve(4);
				unsigned int cExtensions = GetNumberOfExtensions();

				X509_EXTENSION *pExt = NULL;
				for(int i=0; i<(int)cExtensions; ++i)
				{
					pExt = ::X509_CRL_get_ext(m_pCRL, i);
					if(!pExt)
					{
						continue;
					}

					X509_EXTENSION *pDupExt = X509_EXTENSION_dup(pExt);
					X509Extension *pExtension = new X509Extension;
					pExtension->m_pCertExtension = pDupExt;
					vExtensions.push_back(pExtension);
				}
			}

			return vExtensions;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetExtension()
		// Description	    : Returns a particular extension present in this CRL depending
		//                    on the object identifier provided. This method iterates over the NSS
		//                    array of extensions, compare each extension's object identifier with 
		//                    the one provided. If the object identifiers match, this method constructs
		//                    a X509Extension object from that extension and returns it. If the
		//                    object identifiers don't match, this method returns smart pointer to NULL.
		// Return type		: auto_ptr<X509Extension>
		//						Smart pointer to extension.
		// Argument         : const string &OID
		//						Object identifier of extension to get.
		//---------------------------------------------------------------------------------------
		auto_ptr<X509Extension> X509CRL::GetExtension(const asn1::ObjectID &OID) const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to get extension from.");

			X509_EXTENSION *pExt = X509_CRL_get_ext(m_pCRL, ::X509_CRL_get_ext_by_OBJ(m_pCRL, OID.m_pObjectID, -1));
			if(!pExt)
			{
				return auto_ptr<X509Extension>(NULL);
			}

			switch(::OBJ_obj2nid(OID.m_pObjectID))
			{
			case NID_crl_number:
				{
					auto_ptr<X509Extension> pCRLNumberExt(new extensions::CRLNumber);
					pCRLNumberExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pCRLNumberExt;
				}

			case NID_delta_crl:
				{
					auto_ptr<X509Extension> pDeltaCRLIndicator(new extensions::DeltaCRLIndicator);
					pDeltaCRLIndicator->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pDeltaCRLIndicator;
				}

			case NID_issuer_alt_name:
				{
					auto_ptr<X509Extension> pIssuerAltName(new extensions::IssuerAltName);
					pIssuerAltName->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pIssuerAltName;
				}

			default:
				{
					auto_ptr<X509Extension> pExtension(new X509Extension);
					pExtension->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pExtension;
				}
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::AddExtension(const X509Extension &ext)
		{
			if(!m_pCRL)
			{
				m_pCRL = X509_CRL_new();
				if(!m_pCRL)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			int iExtLoc = X509_CRL_add_ext(m_pCRL, ext.m_pCertExtension, -1);
			if(iExtLoc == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::RemoveExtension(const asn1::ObjectID &oid)
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to remove extension from.");

			int Pos = ::X509_CRL_get_ext_by_OBJ(m_pCRL, oid.m_pObjectID, -1);
			X509_EXTENSION *pExt = ::X509_CRL_delete_ext(m_pCRL, Pos);
			if(NULL == pExt)
				return false;

			::X509_EXTENSION_free(pExt);
			return true;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRL::RemoveAllExtensions()
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to remove all extensions from.");

			if(m_pCRL->crl->extensions)
			{
				sk_X509_EXTENSION_pop_free(m_pCRL->crl->extensions, X509_EXTENSION_free);
				m_pCRL->crl->extensions = NULL;
			}
		}

		//---------------------------------------------------------------------------------------
		// Function name	: ToPEM()
		// Description	    : Returns the PEM bytes of this CRL.
		// Return type		: auto_ptr<CByteArray>
		//						Smart pointer to ByteArray containing PEM bytes of this CRL.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::ByteArray X509CRL::ToPEM() const /* throw (Exception) */
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to convert into PEM format.");

			BIO *pBIO = ::BIO_new(BIO_s_mem());
			if(!pBIO)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			PEM_write_bio_X509_CRL(pBIO, m_pCRL);

			char *pBuffer = NULL;
			long lSize = BIO_get_mem_data(pBIO, &pBuffer);

			utils::ByteArray ba(reinterpret_cast<unsigned char *>(pBuffer), lSize);

			int iRet = ::BIO_free(pBIO);
			if(!iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			return ba;

		}



		//---------------------------------------------------------------------------------------
		// Function name	: WriteToDisk()
		// Description	    : Writes the DER or PEM bytes of this CRL on the disk.
		// Return type		: bool
		//						true if all the steps of converting from DER to PEM and writing to 
		//                      disk are successful otherwise false.
		// Argument         : const string &szFileName
		//						Name of the file to write CRL bytes to.
		//					  bool bPEM /*= false*/
		//						whether to write CRL in PEM or DER. If true, the CRL
		//                      will be written in PEM otherwise it will be written in DER. Default
		//                      is false.
		//---------------------------------------------------------------------------------------
		bool X509CRL::WriteToDisk(const string &szFileName, bool bPEM /*= false*/)
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to write onto disk.");

			if(bPEM)
			{
				utils::ByteArray ba = ToPEM();
				utils::File::Save(szFileName, ba);
				return true;
			}
			else
			{
				utils::ByteArray ba = GetEncoded();
				utils::File::Save(szFileName, ba);
				return true;
			}

		}


		//---------------------------------------------------------------------------------------
		// Function name	: FromPEM()
		// Description	    : Creates a CRL object from a ByteArray containing PEM bytes
		//                    of a CRL. Delegates call to member function Construct().
		//                    This method is only used in conjunction with default constructor.
		//                    It throws a Exception if it is called on a CRL object 
		//                    constructed through constructors other than the default constructor.
		//                    In that case, use assignment operator instead.
		// Return type		: bool
		//						true if CRL is constructed successfully otherwise false.
		// Argument         : const CByteArray &PEMData
		//						ByteArray from containing CRL's PEM bytes.
		//---------------------------------------------------------------------------------------
		void X509CRL::FromPEM(const utils::ByteArray &PEMData) /* throw (Exception) */
		{
			X509CRL crl(PEMData);
			if(m_pCRL)
			{
				::X509_CRL_free(m_pCRL);
			}

			m_pCRL = crl.m_pCRL;
			crl.m_pCRL = NULL;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FromDER()
		// Description	    : Creates a CRL object from a ByteArray containing DER bytes
		//                    of a CRL. Delegates call to member function Construct().
		//                    This method is only used in conjunction with default constructor.
		//                    It throws a Exception if it is called on a CRL object 
		//                    constructed through constructors other than the default constructor.
		//                    In that case, use assignment operator instead.
		// Return type		: bool
		//						true if CRL is constructed successfully otherwise false.
		// Argument         : const CByteArray &DERData
		//						ByteArray containing CRL's DER bytes.
		//---------------------------------------------------------------------------------------
		void X509CRL::FromDER(const utils::ByteArray &DERData) /* throw (Exception) */
		{
			X509CRL crl(DERData);
			if(m_pCRL)
			{
				::X509_CRL_free(m_pCRL);
			}

			m_pCRL = crl.m_pCRL;
			crl.m_pCRL = NULL;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::operator==(const X509CRL &rhs)
		{
			if(!rhs.m_pCRL)
				throw InvalidArgumentException("The provided CRL is NULL.");

			if(!m_pCRL)
				throw NullPointerException("There is no CRL to compare from.");

			return ::X509_CRL_cmp(m_pCRL, rhs.m_pCRL) == 0 ? true : false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509CRL::operator!=(const X509CRL &rhs)
		{
			if(!m_pCRL)
				throw NullPointerException("There is no CRL to compare from.");

			return !operator==(rhs);
		}

	}
}

