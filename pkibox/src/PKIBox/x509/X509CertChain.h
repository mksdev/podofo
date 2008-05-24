
#ifndef PKIBOX_X509_X509_CERT_CHAIN_H
#define PKIBOX_X509_X509_CERT_CHAIN_H

#include <vector>
#include "../Exception.h"
#include "../asn1/DistinguishedName.h"
#include "../utils/ByteArray.h"

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
	}
	namespace x509
	{
		//! This class represents a chain of certificates i.e. a hierarchy of EE, SubCA, RootCA.
		template <typename T>
		class X509CertChain  
		{
		public:
			//! Default constructor. Constructs an empty chain.
			X509CertChain() {}

			virtual ~X509CertChain() {}

			void FromByteArray(const PKIBox::utils::ByteArray &baChain)
			{
				const unsigned char * pbData = baChain.GetData();
				unsigned int offset = 0;

				int nNumberOfCertificates = *((int *)pbData);
				offset += sizeof(int);

				for(int i=0 ; i<nNumberOfCertificates ; ++i)
				{
					int nSizeofCertBytes = *((int *)(pbData + offset));
					offset += sizeof(int);

					T certificate( (unsigned char *)(pbData + offset), nSizeofCertBytes );
					offset += nSizeofCertBytes;

					AddCert(certificate);
				}
			}

			PKIBox::utils::ByteArray GetEncoded() const
			{
				unsigned int Size = sizeof(int)/*Number of Certificates*/;
				
				unsigned char *pbData = (unsigned char *)malloc(Size);
				memset(pbData, 0, Size);
				unsigned int offset = 0;

				*(int *)pbData = m_vpCertificates.size();
				offset += sizeof(int);

				for(int i=0 ; i<m_vpCertificates.size() ; ++i)
				{
					PKIBox::utils::ByteArray baCertificateBytes = m_vpCertificates[i].GetEncoded();

					pbData = (unsigned char *)realloc(pbData, offset + sizeof(int) + baCertificateBytes.GetLength());

					*(int *)(pbData + offset) = baCertificateBytes.GetLength();
					offset += sizeof(int);

                    memcpy(pbData + offset, baCertificateBytes.GetData(), baCertificateBytes.GetLength());
					offset += baCertificateBytes.GetLength();
				}

				PKIBox::utils::ByteArray baCertificateChain(pbData, offset);
				if(pbData)
					free(pbData);
				pbData = NULL;

				return baCertificateChain;
			}

			//! Returns the number of certificates in the chain.
			/*!
				\return int: Number of certificates in chain
			*/
			const int GetNumberOfCerts() const 
			{	
				return m_vpCertificates.size();	
			}

			//! Checks whether this X509CertChain is empty or not.
			/*!
				\return bool: whether chain is empty or not
			*/
			bool Empty() const 
			{	
				return m_vpCertificates.empty(); 
			}

			//! An iterator type for iterating over the members of the certificate chain.
			typedef typename std::vector<T>::const_iterator const_iterator;

			//! A reverse iterator type for iterating over the members of the certificate chain in reverse.
			typedef typename std::vector<T>::const_reverse_iterator const_reverse_iterator;

			//! Returns the front of the certificate chain (i.e. the end entity).
			const_iterator begin() const
			{
				return m_vpCertificates.begin();
			}

			//! Returns the rear of the chain.
			const_reverse_iterator rbegin() const
			{
				return m_vpCertificates.rbegin();
			}

			//! Returns the rear of the chain.
			const_iterator end() const
			{
				return m_vpCertificates.end();		
			}

			//! Returns the front of the chain.
			const_reverse_iterator rend() const
			{
				return m_vpCertificates.rend();
			}

			//! Adds any type of certificate into the chain. i.e. EE or CA.
			/*!
				\param const T &Cert: X509 Certificate to be added
			*/
			void AddCert(const T &Cert)  /*throw (CException)*/ 
			{
				if(Cert.IsCACert())
					AddCACert(Cert);
				else
					AddEECert(Cert);
			}

			//! Adds a CA certificate into the chain.
			/*!
				\param const T &Cert: CA Certificate to be added
			*/
			void AddCACert(const T &Cert)  /*throw (CException)*/ 
			{
				if(!Cert.IsCACert())
					throw PKIBox::CException("Cannot add an end entity certificate as CA certificate.");

				if(m_vpCertificates.empty())
				{
					m_vpCertificates.push_back(Cert);
				}
				else 
				{
					std::vector<T>::iterator itBeg = m_vpCertificates.begin();
					std::vector<T>::iterator itEnd = m_vpCertificates.end();

					for(; itBeg < itEnd; ++itBeg)
					{
						T Obj = *itBeg;
						if(Cert.GetIssuerDN() == Obj.GetSubjectDN())
						{
							m_vpCertificates.insert(itBeg, Cert);
							return;
						}
					}

					m_vpCertificates.push_back(Cert);
				}

			}

			//! Adds a EE certificate into the chain.
			/*!
				\param const T &Cert: End Entity certificate to be added
			*/
			void AddEECert(const T &Cert)  /*throw (CException)*/ 
			{
				if(Cert.IsCACert())
					throw CException("Cannot add a CA certificate as end entity certificate.");

				// End entities are always at top.
				m_vpCertificates.insert(m_vpCertificates.begin(), Cert);
			}

			//! Removes a certificate from the chain. 
			/*!
				\param const T &Cert: X509 Certificate to be removed from the chain
			*/
			void RemoveCert(const T &Cert)
			{
				m_vpCertificates.erase(remove(m_vpCertificates.begin(), m_vpCertificates.end(), Cert));
			}

			//! Returns the end-entity certificate (always the start of the chain).
			/*!
				\return const T &: End Entity certificate from the chain
			*/
			const T &GetEECertificate() const
			{
				return m_vpCertificates.front();
			}

			//! Clears this X509Certchain.
			void Clear()
			{
				m_vpCertificates.clear();
			}

			//! Equality operator.
			/*!
				\param const X509CertChain<T> &rhs
				\return bool
			*/
			bool operator==(const X509CertChain<T> &rhs)
			{
				if( GetNumberOfCerts() == rhs.GetNumberOfCerts())
				{
					for(unsigned int i=0; i<m_vpCertificates.size(); ++i)
					{
						if(m_vpCertificates[i] != rhs.m_vpCertificates[i])
							return false;
					}

					return true;
				}

				return false;
			}

			//! Inequality operator.
			/*!
				\param const X509CertChain<T> &rhs
				\return bool
			*/
			bool operator!=(const X509CertChain<T> &rhs)
			{
				return !operator==(rhs);
			}

			//! Subscript version
			/*!
				\param unsigned int Index
				\return const T &
			*/
			const T &operator[](unsigned int Index) const
			{
				return m_vpCertificates[Index];
			}

			//! Subscript version
			/*!
				\param unsigned int Index
				\return T &
			*/
			T &operator[](unsigned int Index)
			{
				return m_vpCertificates[Index];
			}

		private:
			std::vector<T> m_vpCertificates;		// vector of certificates in the chain.

		};
	}
}

#endif // !PKIBOX_X509_X509_CERT_CHAIN_H

