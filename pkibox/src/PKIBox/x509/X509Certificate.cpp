
#include <cassert>
#include "X509Certificate.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../openssl/Globals.h"
#include "../Exception.h"
#include "../NullPointerException.h"
#include "../InvalidArgumentException.h"
#include "../utils/ByteArray.h"
#include "../utils/BigInteger.h"
#include "../utils/DateTime.h"
#include "../utils/File.h"
#include "../asn1/DistinguishedName.h"
#include "../asn1/AlgorithmID.h"
#include "../asn1/OIDs.h"
#include "PublicKey.h"
#include "PrivateKey.h"
#include "X509Extension.h"
#include "extensions/KeyUsage.h"
#include "extensions/ExtendedKeyUsage.h"
#include "extensions/BasicConstraints.h"
#include "extensions/SubjectAltName.h"
#include "extensions/SubjectKeyIdentifier.h"
#include "extensions/CRLDistributionPoints.h"
#include "extensions/AuthorityInformationAccess.h"
#include "extensions/CertificatePolicies.h"

using namespace std;
using namespace PKIBox::utils;


namespace PKIBox
{
	namespace x509
	{
		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate::X509Certificate(void) : m_pCert(NULL)
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
		bool X509Certificate::IsDER(const unsigned char *pbArray)
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
		void X509Certificate::Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (Exception) */
		{
			assert(pbArray != NULL);
			assert(cLength > 0);

			if(IsDER(pbArray)) // DER
			{
				m_pCert = ::d2i_X509(NULL, &pbArray, cLength);
				if(!m_pCert)
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

				m_pCert = PEM_read_bio_X509(pBIO, NULL, NULL, NULL);
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					iRet = ::BIO_free(pBIO);
					throw Exception(pc);
				}

				iRet = ::BIO_free(pBIO);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate::X509Certificate(/*const */unsigned char *pbArray, unsigned int cLength) : m_pCert(NULL) /* throw (Exception)*/
		{
			assert(pbArray != NULL);
			Construct(pbArray, cLength);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		utils::ByteArray X509Certificate::GetEncoded() const /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get in encoded from.");

			utils::ByteArray ba;
			int iSize = ::i2d_X509(m_pCert, NULL);
			if(iSize == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
			iSize = ::i2d_X509(m_pCert, &pEncoded);
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
		X509Certificate::X509Certificate(const utils::ByteArray &ByteArray) : m_pCert(NULL) /* throw (Exception)*/
		{
			if(ByteArray.IsEmpty())
			{
				throw InvalidArgumentException("The provided byte array is empty.");
			}

			unsigned char *puc = const_cast<unsigned char *>( ByteArray.GetData() );
			unsigned int uiSize = ByteArray.GetLength();
			Construct(puc, uiSize);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate::X509Certificate(const char *szFileName) : m_pCert(NULL) /* throw (Exception)*/ 
		{
			assert(szFileName != NULL);

			utils::ByteArray baCert = utils::File::Load(szFileName);
			if(baCert.IsEmpty())
			{
				throw InvalidArgumentException("The specified file is empty.");
			}

			unsigned char *puc = const_cast<unsigned char *>( baCert.GetData() );
			unsigned int uiSize = baCert.GetLength();
			Construct(puc, uiSize);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509Certificate::FromPEM(const utils::ByteArray &PEMData) /* throw (Exception) */
		{
			X509Certificate cert(PEMData);
			if(m_pCert)
			{
				::X509_free(m_pCert);
			}

			m_pCert = cert.m_pCert;
			cert.m_pCert = NULL;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509Certificate::FromDER(const utils::ByteArray &DERData) /* throw (Exception) */
		{
			X509Certificate cert(DERData);
			if(m_pCert)
			{
				::X509_free(m_pCert);
			}

			m_pCert = cert.m_pCert;
			cert.m_pCert = NULL;
		}



		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate::~X509Certificate(void)
		{
			if(m_pCert)
			{
				::X509_free(m_pCert);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate::X509Certificate(const X509Certificate &rhs) 
		{
			m_pCert = X509_dup(rhs.m_pCert);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate &X509Certificate::operator=(const X509Certificate &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if(m_pCert)
			{
				::X509_free(m_pCert);
			}

			// Assign new values
			m_pCert = X509_dup(rhs.m_pCert);

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Certificate &X509Certificate::operator=(const ByteArray &baCert)
		{
			X509Certificate Cert(baCert);

			if(m_pCert)
				::X509_free(m_pCert);

			m_pCert = Cert.m_pCert;
			Cert.m_pCert = NULL;

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		int X509Certificate::GetVersion() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get Version from.");

			return (X509_get_version(m_pCert) + 1);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: SetVersion
		// Description	    : Set the version number of the X509Certificate.
		// Return type		: void
		// Argument         : const unsigned int iVersion
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetVersion(unsigned int iVersion) //throw Exception
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);				
				}
			}

			int iRet = X509_set_version(m_pCert, iVersion);
			if(iRet == -1)
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
		asn1::DistinguishedName X509Certificate::GetSubjectDN() const /* throw (Exception)*/ 
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get Subject DN from.");

			X509_NAME *pX509Name = ::X509_get_subject_name(m_pCert);
			if(!pX509Name)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			asn1::DistinguishedName DN;
			DN.m_pX509Name = X509_NAME_dup(pX509Name);

			return DN;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: SetSubjectDN
		// Description	    : Sets the Subject Distinguished Name of this X509Certificate.
		// Return type		: void
		// Argument         : const DistinguishedName &subjectDN
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetSubjectDN(const asn1::DistinguishedName &subjectDN) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(!m_pCert->cert_info)
				{
					m_pCert->cert_info = X509_CINF_new();
					if(!m_pCert->cert_info)
					{
						if(m_pCert)
							X509_free(m_pCert);

						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}

					if(!m_pCert->cert_info->subject)
					{
						m_pCert->cert_info->subject = X509_NAME_new();
						if(!m_pCert->cert_info->subject)
						{
							if(m_pCert)
								X509_free(m_pCert);

							if(m_pCert->cert_info)
								X509_CINF_free(m_pCert->cert_info);

							const char *pc = ::ERR_reason_error_string(::ERR_get_error());
							throw Exception(pc);
						}
					}
				}
			}

			int iRet = X509_set_subject_name( m_pCert, subjectDN.m_pX509Name );
			if(iRet == -1)
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
		asn1::DistinguishedName X509Certificate::GetIssuerDN() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get Issuer DN from.");

			X509_NAME *pX509Name = ::X509_get_issuer_name(m_pCert);
			if(!pX509Name)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			asn1::DistinguishedName DN;
			DN.m_pX509Name = X509_NAME_dup(pX509Name);

			return DN;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: SetSubjectDN
		// Description	    : Sets the Issuer Distinguished Name of this X509Certificate.
		// Return type		: void
		// Argument         : const DistinguishedName &issuerDN
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetIssuerDN(const asn1::DistinguishedName &IssuerDN) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(!m_pCert->cert_info)
				{
					m_pCert->cert_info = X509_CINF_new();
					if(!m_pCert->cert_info)
					{
						if(m_pCert)
							X509_free(m_pCert);

						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}

					if(!m_pCert->cert_info->issuer)
					{
						m_pCert->cert_info->issuer = X509_NAME_new();
						if(!m_pCert->cert_info->issuer)
						{
							if(m_pCert)
								X509_free(m_pCert);

							if(m_pCert->cert_info)
								X509_CINF_free(m_pCert->cert_info);

							const char *pc = ::ERR_reason_error_string(::ERR_get_error());
							throw Exception(pc);
						}
					}
				}
			}

			int iRet = X509_set_issuer_name(m_pCert, IssuerDN.m_pX509Name);
			if(iRet == -1)
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
		utils::BigInteger X509Certificate::GetSerialNumber() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get SerialNumber from.");

			ASN1_INTEGER *pASN1Integer = ::X509_get_serialNumber(m_pCert);
			if(!pASN1Integer)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			BIGNUM *pBN = ::ASN1_INTEGER_to_BN(pASN1Integer, NULL);
			if(!pBN)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			BigInteger serialNumber;
			serialNumber.m_pBN = pBN;
			return serialNumber;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: SetSerialNumber
		// Description	    : Sets the serial number of this X509Certificate.
		// Return type		: void
		// Argument         : const string &serialNumber
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetSerialNumber(const utils::BigInteger &serialNumber) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			ASN1_INTEGER *pSerialNumber = ::BN_to_ASN1_INTEGER(serialNumber.m_pBN, NULL);
			if(!pSerialNumber)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			m_pCert->cert_info->serialNumber = pSerialNumber;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		utils::DateTime X509Certificate::GetNotBefore() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to get NotBefore from.");

			time_t Time = 0;
			ASN1_TIME *pNotBefore = X509_get_notBefore(m_pCert);
			if(!pNotBefore)
				throw NullPointerException("Could not get NotBefore.");

			switch(pNotBefore->type)
			{
			case V_ASN1_UTCTIME:
				Time = ::ASN1_UTCTIME_get(pNotBefore);
				break;

			case V_ASN1_GENERALIZEDTIME:
				Time = ::ASN1_GENERALIZEDTIME_get(pNotBefore);
				break;

			default:
				throw Exception("Invalid time format.");

			}

			return utils::DateTime(Time);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: SetNotBefore
		// Description	    : Sets the NotBefore date of the X509Certificate.
		// Return type		: void
		// Argument         : const CDate &notBefore
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetNotBefore(const utils::DateTime &notBefore) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			int iRet = X509_set_notBefore(m_pCert, ASN1_UTCTIME_set(NULL, notBefore.GetTime()) );
			if(iRet == -1)
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
		utils::DateTime X509Certificate::GetNotAfter() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to get NotAfter from.");

			time_t Time = 0;
			ASN1_TIME *pNotAfter = X509_get_notAfter(m_pCert);
			if(!pNotAfter)
				throw NullPointerException("Could not get NotAfter.");

			switch(pNotAfter->type)
			{
			case V_ASN1_UTCTIME:
				Time = ::ASN1_UTCTIME_get(pNotAfter);
				break;

			case V_ASN1_GENERALIZEDTIME:
				Time = ::ASN1_GENERALIZEDTIME_get(pNotAfter);
				break;

			default:
				throw Exception("Invalid time format.");

			}

			return utils::DateTime(Time);

		}

		//---------------------------------------------------------------------------------------
		// Function name	: SetNotAfter
		// Description	    : Sets the NotAfter date of this X509Certificate.
		// Return type		: void
		// Argument         : const CDate &notAfter
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetNotAfter(const utils::DateTime &notAfter) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			int iRet = X509_set_notAfter(m_pCert, ASN1_UTCTIME_set(NULL, notAfter.GetTime()) );
			if(iRet == -1)
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
		PublicKey X509Certificate::GetPublicKey() const /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get PublicKey from.");

			EVP_PKEY *pKey = ::X509_get_pubkey(m_pCert);
			if(!pKey)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			PublicKey PublicKey;
			PublicKey.m_pKey = pKey;
			return PublicKey;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: SetPublicKey
		// Description	    : Sets the Public key of this X509Certificate.
		// Return type		: void
		// Argument         : const PublicKey &pKey
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetPublicKey(const PublicKey &pKey) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			int iRet = X509_set_pubkey(m_pCert, pKey.m_pKey);
			if(iRet == -1)
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
		auto_ptr<asn1::AlgorithmID> X509Certificate::GetSignatureAlgorithm() const /* throw (Exception) */ 
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to get signature algorithm from.");

			if(m_pCert->sig_alg)
			{
				auto_ptr<asn1::AlgorithmID> pAlgID(new asn1::AlgorithmID );
				pAlgID->m_pAlgID = X509_ALGOR_dup(m_pCert->sig_alg);
				return pAlgID;
			}

			return auto_ptr<asn1::AlgorithmID>(NULL);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: SetSignatureAlgorithm
		// Description	    : Sets the signature algorithm of this X509Certificate.
		// Return type		: void
		// Argument         : const AlgorithmID &algID
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetSignatureAlgorithm(const asn1::AlgorithmID &algID) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}			
			}

			m_pCert->sig_alg = X509_ALGOR_dup(algID.m_pAlgID);
			if(!m_pCert->sig_alg)
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
		utils::ByteArray X509Certificate::GetSignature() const /* throw (Exception) */ 
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to get signature from.");

			utils::ByteArray ba;
			int iSize = ::i2d_ASN1_BIT_STRING(m_pCert->signature, NULL);
			if(iSize == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
			iSize = ::i2d_ASN1_BIT_STRING(m_pCert->signature, &pEncoded);
			pEncoded -= iSize;

			ba.Set(pEncoded, iSize);

			::free(pEncoded);  // Deallocate

			return ba;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: SetSignature
		// Description	    : Sets the signature of this X509Certificate.
		// Return type		: void
		// Argument         : const CByteArray &baSignature
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::SetSignature(const utils::ByteArray &baSignature) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);				
				}
			}

			unsigned char * pszSignature = (unsigned char *) ::malloc( baSignature.GetLength() );
			sprintf( (char *)pszSignature, "%s", baSignature.GetData() );

			m_pCert->signature = ::d2i_ASN1_BIT_STRING(NULL, (const unsigned char **)&pszSignature, (long)baSignature.GetLength() );

			pszSignature -= baSignature.GetLength();

			if(!m_pCert->signature)
			{
				if(pszSignature)
					::free(pszSignature);

				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);				
			}

			if(pszSignature)
				::free(pszSignature);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		utils::ByteArray X509Certificate::ToPEM() const /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to convert into PEM format.");

			BIO *pBIO = ::BIO_new(BIO_s_mem());
			if(!pBIO)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			PEM_write_bio_X509(pBIO, m_pCert);

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
		// Description	    : Writes the DER or PEM bytes of this Certificate on the disk.
		// Return type		: bool
		//						true if all the steps of converting from DER to PEM and writing to 
		//                      disk are successful otherwise false.
		// Argument         : const string &szFileName
		//						Name of the file to write certificate bytes to.
		//					  bool bPEM /*= false*/
		//						whether to write certificate in PEM or DER. If true, the certificate
		//                      will be written in PEM otherwise it will be written in DER. Default
		//                      is false.
		//---------------------------------------------------------------------------------------
		bool X509Certificate::WriteToDisk(const string &szFileName, bool bPEM /*= false*/) /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to write onto disk.");

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
		// Function name	: Sign
		// Description	    : Signs a certificate using the given algorithm and the private key of the issuer.
		// Return type		: void
		// Argument         : const AlgorithmID &algID, const PrivateKey &pKey
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::Sign(const asn1::AlgorithmID &algID, const PrivateKey &pKey) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				throw NullPointerException("There is no certificate to sign.");
			}

			int iRet = ::X509_sign(m_pCert, pKey.m_pPrivateKey, EVP_get_digestbyobj( algID.GetAlgorithm().m_pObjectID ) );
			if(iRet == -1)
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
		bool X509Certificate::Verify(PublicKey &Key) /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to verify.");

			int iRet = ::X509_verify(m_pCert, Key.m_pKey);
			if(iRet != 1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			return true;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Certificate::Verify(const X509Certificate &IssuerCert) /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to verify.");

			int iRet = ::X509_verify(m_pCert, IssuerCert.GetPublicKey().m_pKey);
			if(iRet != 1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			return true;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Certificate::HasExtensions() const /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to check extensions for.");

			return m_pCert->cert_info->extensions != NULL;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		unsigned int X509Certificate::GetNumberOfExtensions() const
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to get number of extensions from.");

			return ::X509_get_ext_count(m_pCert);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		auto_ptr<X509Extension> X509Certificate::GetExtension(const asn1::ObjectID &OID) const /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to get extension from.");

			int Pos = ::X509_get_ext_by_OBJ(m_pCert, OID.m_pObjectID, -1);
			X509_EXTENSION *pExt = X509_get_ext(m_pCert, Pos);
			if(!pExt)
			{
				return auto_ptr<X509Extension>(NULL);
			}

			switch(::OBJ_obj2nid(OID.m_pObjectID))
			{
			case NID_key_usage:
				{
					auto_ptr<X509Extension> pKeyUsageExt(new extensions::KeyUsage);
					pKeyUsageExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pKeyUsageExt;
				}

			case NID_ext_key_usage:
				{
					auto_ptr<X509Extension> pExtKeyUsageExt(new extensions::ExtendedKeyUsage);
					pExtKeyUsageExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pExtKeyUsageExt;
				}

			case NID_info_access:
				{
					auto_ptr<X509Extension> pAIAExt(new extensions::AuthorityInformationAccess);
					pAIAExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pAIAExt;
				}

			case NID_crl_distribution_points:
				{
					auto_ptr<X509Extension> pCRLDistPointsExt(new extensions::CRLDistributionPoints);
					pCRLDistPointsExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pCRLDistPointsExt;
				}

			case NID_basic_constraints:
				{
					auto_ptr<X509Extension> pBasicConstraintExt(new extensions::BasicConstraints);
					pBasicConstraintExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pBasicConstraintExt;
				}

			case NID_subject_alt_name:
				{
					auto_ptr<X509Extension> pSubjectAltNameExt(new extensions::SubjectAltName);
					pSubjectAltNameExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pSubjectAltNameExt;
				}

			case NID_subject_key_identifier:
				{
					auto_ptr<X509Extension> pSubjectKeyIDExt(new extensions::SubjectKeyIdentifier);
					pSubjectKeyIDExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pSubjectKeyIDExt;
				}

			case NID_certificate_policies:
				{
					auto_ptr<X509Extension> pCertPoliciesExt(new extensions::CertificatePolicies);
					pCertPoliciesExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pCertPoliciesExt;
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
		vector< clone_ptr<X509Extension> > X509Certificate::GetExtensions() const /* throw (Exception) */
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to get extensions from.");

			vector< clone_ptr<X509Extension> > vExtensions;
			if(m_pCert->cert_info->extensions)
			{
				vExtensions.reserve(7);
				unsigned int cExtensions = GetNumberOfExtensions();

				X509_EXTENSION *pExt = NULL;
				for(int i=0; i<(int)cExtensions; ++i)
				{
					pExt = ::X509_get_ext(m_pCert, i);
					if(!pExt)
					{
						continue;
					}

					X509_EXTENSION *pDupExt = X509_EXTENSION_dup(pExt);
					X509Extension *pExt = new X509Extension;
					pExt->m_pCertExtension = pDupExt;
					vExtensions.push_back(pExt);
				}
			}

			return vExtensions;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: AddExtension
		// Description	    : Adds the given X509v3 extension in this X509Certificate. 
		// Return type		: void
		// Argument         : const X509Extension &extension
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::AddExtension(const X509Extension &extension) /* throw (Exception)*/
		{
			if(!m_pCert)
			{
				m_pCert = X509_new();
				if(!m_pCert)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(!m_pCert->cert_info)
				{
					m_pCert->cert_info = X509_CINF_new();
					if(!m_pCert->cert_info)
					{
						if(m_pCert)
							X509_free(m_pCert);

						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
			}

			int iExtLoc = X509_add_ext(m_pCert, extension.m_pCertExtension, -1);
			if(iExtLoc == -1)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: RemoveExtension
		// Description	    : Removes the extension specified by its object identifier from this X509Certificate.
		// Return type		: void
		// Argument         : const ObjectID &OID
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::RemoveExtension(const asn1::ObjectID &OID) /* throw (Exception)*/
		{	
			if(!m_pCert)
				throw NullPointerException("There is no certificate to remove extension from.");

			int Pos = ::X509_get_ext_by_OBJ(m_pCert, OID.m_pObjectID, -1);
			X509_EXTENSION *pExt = X509_delete_ext(m_pCert, Pos);

			if(!pExt)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

		}

		//---------------------------------------------------------------------------------------
		// Function name	: RemoveAllExtensions
		// Description	    : Removes all extensions from this X509Certificate.
		// Return type		: void
		// Argument         : void
		// Code Added By	: GA
		//---------------------------------------------------------------------------------------
		void X509Certificate::RemoveAllExtensions()/* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no certificate to remove extensions from.");

			int iLocs = sk_num(m_pCert->cert_info->extensions);

			for(int iCount=0 ; iCount<iLocs ; iCount++)
				sk_delete(m_pCert->cert_info->extensions, iCount);

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Certificate::IsCACert() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to check for CA.");

			auto_ptr<X509Extension> pExt = GetExtension(asn1::OIDs::id_ce_basicConstraints);
			auto_ptr<extensions::BasicConstraints> pBasicConstExt( dynamic_cast< extensions::BasicConstraints * >(pExt.release()));
			if(pBasicConstExt.get())
			{
				return pBasicConstExt->GetCA();
			}
			else
			{
				// Check for version 1 certificate. V1 certificates don't have BC extension.
				if( (0 == X509_get_version(m_pCert)) && IsSelfSigned())
				{
					return true;
				}
			}

			return false;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Certificate::IsSelfSigned() const /* throw (Exception)*/
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to check for self signed.");

			int iRet = ::X509_verify(m_pCert, GetPublicKey().m_pKey);
			if(iRet != 1)
			{
				return false;
			}

			return true;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Certificate::operator==(const X509Certificate &rhs)
		{
			if(!rhs.m_pCert)
				throw InvalidArgumentException("The provided certificate is NULL.");

			if(!m_pCert)
				throw NullPointerException("There is no Certificate to compare from.");

			return ::X509_cmp(m_pCert, rhs.m_pCert) == 0 ? true : false;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Certificate::operator!=(const X509Certificate &rhs)
		{
			if(!m_pCert)
				throw NullPointerException("There is no Certificate to compare from.");

			return !operator==(rhs);
		}
	}
}

