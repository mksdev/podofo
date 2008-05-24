
#include "TimeSpan.h"

const int maxTimeBufferSize = 128;

namespace PKIBox
{
	namespace utils
	{
		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan::TimeSpan() : m_TimeSpan(0)
		{

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan::TimeSpan( time_t Time ) : m_TimeSpan(Time)
		{

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan::TimeSpan(long lDays, int nHours, int nMins, int nSecs)
		{
			m_TimeSpan = nSecs + 60* (nMins + 60* (nHours + time_t(24) * lDays));
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetDays() const
		{
			return( m_TimeSpan/(24*3600) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetTotalHours() const
		{
			return( m_TimeSpan/3600 );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetHours() const
		{
			return( long( GetTotalHours()-(GetDays()*24) ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetTotalMinutes() const
		{
			return( m_TimeSpan/60 );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetMinutes() const
		{
			return( long( GetTotalMinutes()-(GetTotalHours()*60) ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetTotalSeconds() const
		{
			return( m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		long TimeSpan::GetSeconds() const
		{
			return( long( GetTotalSeconds()-(GetTotalMinutes()*60) ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		time_t TimeSpan::GetTimeSpan() const
		{
			return( m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan TimeSpan::operator+( TimeSpan rhs ) const 
		{
			return( TimeSpan( m_TimeSpan + rhs.m_TimeSpan ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan TimeSpan::operator-( TimeSpan rhs ) const 
		{
			return( TimeSpan( m_TimeSpan - rhs.m_TimeSpan ) );
		}



		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan& TimeSpan::operator+=( TimeSpan rhs )
		{
			m_TimeSpan += rhs.m_TimeSpan;
			return( *this );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		TimeSpan& TimeSpan::operator-=( TimeSpan rhs )
		{
			m_TimeSpan -= rhs.m_TimeSpan;
			return( *this );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool TimeSpan::operator==( TimeSpan rhs ) const
		{
			return( m_TimeSpan == rhs.m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool TimeSpan::operator!=( TimeSpan rhs ) const
		{
			return( m_TimeSpan != rhs.m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool TimeSpan::operator<( TimeSpan rhs ) const
		{
			return( m_TimeSpan < rhs.m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool TimeSpan::operator>( TimeSpan rhs ) const
		{
			return( m_TimeSpan > rhs.m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool TimeSpan::operator<=( TimeSpan rhs ) const
		{
			return( m_TimeSpan <= rhs.m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool TimeSpan::operator>=( TimeSpan rhs ) const 
		{
			return( m_TimeSpan >= rhs.m_TimeSpan );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		std::string TimeSpan::Format(const char *pFormat) const
		{
			using namespace std;

			string strBuffer;
			char buffer[maxTimeBufferSize] = {0};

			char ch = NULL;
			while ((ch = *pFormat++) != '\0')
			{
				if (ch == '%')
				{
					switch (ch = *pFormat++)
					{
					case '%':
						strBuffer += ch;
						break;
					case 'D':
						sprintf(buffer, "%I64d", GetDays());
						strBuffer += buffer;
						break;
					case 'H':
						sprintf(buffer, "%02ld", GetHours());
						strBuffer += buffer;
						break;
					case 'M':
						sprintf(buffer, "%02ld", GetMinutes());
						strBuffer += buffer;
						break;
					case 'S':
						sprintf(buffer, "%02ld", GetSeconds());
						strBuffer += buffer;
						break;
					default:
						break;
					}
				}
				else
				{
					strBuffer += ch;
				}
			}

			return strBuffer;
		}
	}
}

