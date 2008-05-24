
#include "BigInteger.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/bn.h>

#define BN_negate(x)	  ((x)->neg = (!((x)->neg)) & 1)

#include "../NullPointerException.h"
#include "../InvalidArgumentException.h"
#include "ArithmeticException.h"
#include "ByteArray.h"

using namespace std;

namespace PKIBox
{
	namespace utils
	{
		const BigInteger BigInteger::ZERO(0);
		const BigInteger BigInteger::ONE(1);

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::BigInteger(void) : m_pBN(NULL)
		{

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::BigInteger(unsigned long val) : m_pBN(NULL)
		{
			m_pBN = BN_new();
			int iRet = 0;
			if(0 == val)
			{
				iRet = BN_zero(m_pBN);
			}
			else if(1 == val)
			{
				iRet = BN_one(m_pBN);
			}
			else
			{
				iRet = BN_set_word(m_pBN, val);
			}

			if(0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(m_pBN)
					BN_free(m_pBN);

				throw InvalidArgumentException(pc);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::BigInteger(const std::string &val): m_pBN(NULL)
		{
			int iRet = ::BN_dec2bn(&m_pBN, val.c_str());
			if(!m_pBN)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw InvalidArgumentException(pc);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::BigInteger(const std::string &val, Radix radix): m_pBN(NULL)
		{
			int iRet = 0;

			switch(radix)
			{
			case BN_DECIMAL:
				iRet = ::BN_dec2bn(&m_pBN, val.c_str());
				if(!m_pBN)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw InvalidArgumentException(pc);
				}
				break;

			case BN_HEXADECIMAL:
				iRet = ::BN_hex2bn(&m_pBN, val.c_str());
				if(!m_pBN)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw InvalidArgumentException(pc);
				}
				break;

			default:
				throw InvalidArgumentException("The specified radix is not supported.");
			}

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::BigInteger(const ByteArray &val): m_pBN(NULL)
		{
			m_pBN = BN_bin2bn(val.GetData(), val.GetLength(), NULL);
			if(!m_pBN)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw InvalidArgumentException(pc);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::BigInteger(const BigInteger &rhs): m_pBN(NULL)
		{
			m_pBN = ::BN_dup(rhs.m_pBN);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator=(const BigInteger &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if(m_pBN)
				::BN_clear_free(m_pBN);

			// Assign new values
			m_pBN = ::BN_dup(rhs.m_pBN);

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator=(unsigned long rhs)
		{
			BIGNUM *pBN = BN_new();
			int iRet = BN_set_word(m_pBN, rhs);
			if(0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					BN_free(pBN);

				throw InvalidArgumentException(pc);
			}

			// delete already allocated memory
			if(m_pBN)
				::BN_clear_free(m_pBN);

			// Assign new values
			m_pBN = pBN;

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator=(const ByteArray &rhs)
		{
			BIGNUM *pBN = BN_bin2bn(rhs.GetData(), rhs.GetLength(), NULL);
			if(!pBN)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					BN_free(pBN);

				throw InvalidArgumentException(pc);
			}

			// delete already allocated memory
			if(m_pBN)
				::BN_clear_free(m_pBN);

			// Assign new values
			m_pBN = pBN;

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger::~BigInteger(void)
		{
			if(m_pBN)
				::BN_clear_free(m_pBN);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool BigInteger::operator==(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			return BN_cmp(m_pBN, rhs.m_pBN) == 0 ? true : false;
		}



		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool BigInteger::operator!=(const BigInteger &rhs) const
		{
			return !operator==(rhs);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool BigInteger::operator<(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			return BN_cmp(m_pBN, rhs.m_pBN) == -1 ? true : false;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool BigInteger::operator>(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			return BN_cmp(m_pBN, rhs.m_pBN) == 1 ? true : false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool BigInteger::operator<=(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			int iRet = BN_cmp(m_pBN, rhs.m_pBN);

			if( (iRet == -1) || (iRet == 0) )
				return true;

			return false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool BigInteger::operator>=(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			int iRet = BN_cmp(m_pBN, rhs.m_pBN);

			if( (iRet == 1) || (iRet == 0) )
				return true;

			return false;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		string BigInteger::ToString(Radix radix) const
		{
			if(!m_pBN)
				throw NullPointerException();

			char *pc = NULL;

			switch(radix)
			{
			case BN_DECIMAL:
				pc = ::BN_bn2dec(m_pBN);
				break;

			case BN_HEXADECIMAL:
				pc = ::BN_bn2hex(m_pBN);
				break;

			default:
				throw InvalidArgumentException("The specified radix is not supported.");
			}

			if(!pc)
				return "";

			string s(pc);
			OPENSSL_free(pc);
			return s;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		unsigned long BigInteger::ToULong() const
		{
			if(!m_pBN)
				throw NullPointerException();

			return ::BN_get_word(m_pBN);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		ByteArray BigInteger::ToByteArray() const
		{
			if(!m_pBN)
				throw NullPointerException();

			int iLength = 0;
			unsigned char *pBuffer = NULL;
			ByteArray ba;
			if(BN_is_negative(m_pBN))
			{
				iLength = BN_num_bytes(m_pBN);
				pBuffer = (unsigned char *)malloc(iLength+1);
				iLength = ::BN_bn2bin(m_pBN, pBuffer+1);
				pBuffer[0] = 0x80; // BN_bn2bin() will not output the sign of a number. So, we are making it explicitly.
				ba.Set(pBuffer, iLength+1);
			}
			else
			{
				int iLength = BN_num_bytes(m_pBN);
				pBuffer = (unsigned char *)malloc(iLength);
				iLength = ::BN_bn2bin(m_pBN, pBuffer);
				ba.Set(pBuffer, iLength);
			}

			if(pBuffer)
				free(pBuffer);
			return ba;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::operator+(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_add(pBN, m_pBN, rhs.m_pBN);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::operator-(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_sub(pBN, m_pBN, rhs.m_pBN);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator-=(const BigInteger &rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_sub(pBN, m_pBN, rhs.m_pBN);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator+=(const BigInteger &rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_add(pBN, m_pBN, rhs.m_pBN);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator<<(int iTimes)
		{
			if(!m_pBN)
				throw NullPointerException();

			BIGNUM *pBN = ::BN_new();
			int iRet = 0;
			if(1 == iTimes)
			{
				iRet = ::BN_lshift1(pBN, m_pBN);
			}
			else
			{
				iRet = ::BN_lshift(pBN, m_pBN, iTimes);
			}
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;

			return *this;

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator>>(int iTimes)
		{
			if(!m_pBN)
				throw NullPointerException();

			BIGNUM *pBN = ::BN_new();
			int iRet = 0;
			if(1 == iTimes)
			{
				iRet = ::BN_rshift1(pBN, m_pBN);
			}
			else
			{
				iRet = ::BN_rshift(pBN, m_pBN, iTimes);
			}

			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;
			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::operator*(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_mul(pBN, m_pBN, rhs.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::operator/(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_div(pBN, NULL, m_pBN, rhs.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator*=(const BigInteger &rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_mul(pBN, m_pBN, rhs.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;
			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator/=(const BigInteger &rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_div(pBN, NULL, m_pBN, rhs.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;
			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::GCD(const BigInteger &val) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!val.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_gcd(pBN, m_pBN, val.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::Reciprocal() const
		{
			if(!m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_reciprocal(pBN, m_pBN, 0, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::Square() const
		{
			if(!m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_sqr(pBN, m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::operator%(const BigInteger &rhs) const
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_mod(pBN, m_pBN, rhs.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator%=(const BigInteger &rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!rhs.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_mod(pBN, m_pBN, rhs.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			if(m_pBN)
				::BN_clear_free(m_pBN);

			m_pBN = pBN;
			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator+=(unsigned long rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			int iRet = ::BN_add_word(m_pBN, rhs);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw ArithmeticException(pc);
			}

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator-=(unsigned long rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			int iRet = ::BN_sub_word(m_pBN, rhs);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw ArithmeticException(pc);
			}

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator*=(unsigned long rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			int iRet = ::BN_mul_word(m_pBN, rhs);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw ArithmeticException(pc);
			}

			return *this;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator/=(unsigned long rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			int iRet = ::BN_div_word(m_pBN, rhs);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw ArithmeticException(pc);
			}

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		unsigned long BigInteger::operator%(unsigned long rhs)
		{
			if(!m_pBN)
				throw NullPointerException();

			unsigned long iRet = ::BN_mod_word(m_pBN, rhs);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw ArithmeticException(pc);
			}

			return iRet;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger &BigInteger::operator-()
		{
			if(!m_pBN)
				throw NullPointerException();

			BN_negate(m_pBN);

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		BigInteger BigInteger::Power(const BigInteger &exponent)
		{
			if(!m_pBN)
				throw NullPointerException();

			if(!exponent.m_pBN)
				throw NullPointerException();

			BN_CTX *pBNCTX = ::BN_CTX_new();
			BIGNUM *pBN = ::BN_new();
			int iRet = ::BN_mod(pBN, m_pBN, exponent.m_pBN, pBNCTX);
			if( 0 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pBNCTX)
					::BN_CTX_free(pBNCTX);

				if(pBN)
					::BN_free(pBN);

				throw ArithmeticException(pc);
			}

			if(pBNCTX)
				::BN_CTX_free(pBNCTX);

			BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}
	}
}


