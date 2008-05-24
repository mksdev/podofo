
#ifndef PKIBOX_UTILS_BIG_INTEGER_H
#define PKIBOX_UTILS_BIG_INTEGER_H

typedef struct bignum_st BIGNUM;

#include <string>

namespace PKIBox
{
	namespace crypto
	{
		class CDSAParameterSpec;
	}

	namespace security
	{
		namespace dsa
		{
			class CDSAKeyPairGenerator;
		}
	}

	namespace x509
	{
		class X509Certificate;
		class X509CRLEntry;
		class X509CRL;
		namespace extensions
		{
			class CRLNumber;
			class DeltaCRLIndicator;
		}
	}

	namespace pkcs7
	{
		class CIssuerAndSerialNumber;
		class CRecipientInfo;
	}

	namespace utils
	{
		class ByteArray;

		//! This class represents a very large integer.
		/*! 
			BigInteger has virtually no limits on the upper bound of numbers. The size of the number that
			a BigInteger variable can hold is limited only by available memory.
		*/
		class BigInteger
		{
			friend class crypto::CDSAParameterSpec;
			friend class security::dsa::CDSAKeyPairGenerator;
			friend class x509::X509Certificate;
			friend class x509::X509CRLEntry;
			friend class x509::X509CRL;
			friend class x509::extensions::CRLNumber;
			friend class x509::extensions::DeltaCRLIndicator;
			friend class pkcs7::CIssuerAndSerialNumber;
			friend class pkcs7::CRecipientInfo;

		public:
			enum Radix
			{
				BN_DECIMAL,
				BN_HEXADECIMAL
			};

			//! The BigInteger constant zero.
			static const BigInteger ZERO;

			//! The BigInteger constant one.
			static const BigInteger ONE;

			//! Default constructor
			BigInteger(void);

			//! Constructs a BigInteger from an unsigned long.
			/*!
				\param unsigned long val
			*/
			explicit BigInteger(unsigned long val);

			//! Translates the decimal String representation of a BigInteger into a BigInteger.
			/*!
				\param const std::string &val
			*/
			explicit BigInteger(const std::string &val);

			//! Translates the String representation of a BigInteger in the specified radix into a BigInteger.
			/*!
				\param const std::string &val
				\param Radix radix
			*/
			BigInteger(const std::string &val, Radix radix);

			//! Translates a byte array containing the two's-complement binary representation of a BigInteger into a BigInteger.
			/*!
				\param const ByteArray &val
			*/
			explicit BigInteger(const ByteArray &val);

			//! Copy constructor.
			/*!
				\param const BigInteger &rhs
			*/
			BigInteger(const BigInteger &rhs);

			//! Copy assignment operator.
			/*!
				\param const BigInteger &rhs
				\return BigInteger &
			*/
			BigInteger &operator=(const BigInteger &rhs);

			//! Assignment operator.
			/*!
				\param unsigned long rhs
				\return BigInteger &
			*/
			BigInteger &operator=(unsigned long rhs);

			//! Assignment operator.
			/*!
				\param const ByteArray &rhs
				\return BigInteger &
			*/
			BigInteger &operator=(const ByteArray &rhs);

			//! Destructor
			virtual ~BigInteger(void);

			//! Returns a byte array containing the two's-complement representation of this BigInteger. 
			/*!
				\return ByteArray  
			*/
			ByteArray ToByteArray() const; 

			//! Returns the string representation of this BigInteger depending on radix.
			/*!
				\param Radix radix
				\return std::string 
			*/
			std::string ToString(Radix radix) const;

			//! Returns the unsigned long representation of this BigInteger
			/*!
				\return unsigned long 
			*/
			unsigned long ToULong() const;

			//! Comparison equality operator
			/*!
				\param const BigInteger &rhs
				\return bool
			*/
			bool operator==(const BigInteger &rhs) const;

			//! Comparison not equal operator
			/*!
				\param const BigInteger &rhs
				\return bool
			*/
			bool operator!=(const BigInteger &rhs) const;

			//! Comparison less than operator
			/*!
				\param const BigInteger &rhs
				\return bool
			*/
			bool operator<(const BigInteger &rhs) const;

			//! Comparison greater than operator
			/*!
				\param const BigInteger &rhs
				\return bool
			*/
			bool operator>(const BigInteger &rhs) const;

			//! Comparison less than or equal to operator
			/*!
				\param const BigInteger &rhs
				\return bool
			*/
			bool operator<=(const BigInteger &rhs) const;

			//! Comparison greater than or equal to operator
			/*!
				\param const BigInteger &rhs
				\return bool
			*/
			bool operator>=(const BigInteger &rhs) const;

			//! Arithmetic operators.
			BigInteger operator+(const BigInteger &rhs) const;
			BigInteger operator-(const BigInteger &rhs) const;
			BigInteger operator*(const BigInteger &rhs) const;
			BigInteger operator/(const BigInteger &rhs) const;
			BigInteger operator%(const BigInteger &rhs) const;
			BigInteger &operator+=(const BigInteger &rhs);
			BigInteger &operator-=(const BigInteger &rhs);
			BigInteger &operator*=(const BigInteger &rhs);
			BigInteger &operator/=(const BigInteger &rhs);
			BigInteger &operator%=(const BigInteger &rhs);

			BigInteger &operator-();

			//! Shift operators.
			BigInteger &operator<<(int iTimes);
			BigInteger &operator>>(int iTimes);

			//! Returns a BigInteger whose value is the greatest common divisor of abs(this) and abs(val). 
			/*!
				\param const BigInteger &val
				\return BigInteger 
			*/
			BigInteger GCD(const BigInteger &val) const;

			//! Returns a BigInteger whose value is the reciprocal of abs(this) and abs(val). 
			/*!
				\return BigInteger 
			*/
			BigInteger Reciprocal() const;

			//! Returns a BigInteger whose value is the sqr(this). 
			/*!
				\return BigInteger 
			*/
			BigInteger Square() const;

			//! Returns a BigInteger whose value is this raised to power exponent. 
			/*!
				\param const BigInteger &exponent
				\return BigInteger 
			*/
			BigInteger Power(const BigInteger &exponent); 

			//! Arithmetic operators.
			BigInteger &operator+=(unsigned long rhs);
			BigInteger &operator-=(unsigned long rhs);
			BigInteger &operator*=(unsigned long rhs);
			BigInteger &operator/=(unsigned long rhs);
			unsigned long operator%(unsigned long rhs);

		private:
			BIGNUM	*m_pBN;
		};
	}
}

#endif // !PKIBOX_UTILS_BIG_INTEGER_H

