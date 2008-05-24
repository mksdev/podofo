
#include <cassert>
#include "TimeSpan.h"
#include "DateTime.h"

#define maxTimeBufferSize       128

// determine number of elements in an array (not bytes)
#define COUNTOF(array) (sizeof(array)/sizeof(array[0]))

namespace PKIBox
{
	namespace utils
	{
		//---------------------------------------------------------------------------------------
		// Function name	: DateTime()
		// Description	    : Default constructor. Initializes m_Time to 0.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		DateTime::DateTime() : m_Time(0)
		{ 

		}


		//---------------------------------------------------------------------------------------
		// Function name	: DateTime()
		// Description	    : One argument constructor. Constructs a Date object from time_t.
		// Return type		: Nothing
		// Argument         : time_t Time
		//						time_t from which to construct a Date object.
		//---------------------------------------------------------------------------------------
		DateTime::DateTime(time_t Time) : m_Time(Time) 
		{ 

		}


		//---------------------------------------------------------------------------------------
		// Function name	: DateTime()
		// Description	    : One argument constructor. Constructs a Date object from a C language
		//                    tm structure.
		// Return type		: Nothing
		// Argument         : const tm *ptm
		//						pointer to the tm structure from which to construct the Date object.
		//---------------------------------------------------------------------------------------
		DateTime::DateTime(const tm *ptm)
		{
			assert(ptm != NULL);
			m_Time = ::mktime(const_cast<tm *>(ptm));
		}


		//---------------------------------------------------------------------------------------
		// Function name	: DateTime()
		// Description	    : Copy constructor.
		// Return type		: Nothing
		// Argument         : const DateTime &DateSrc
		//---------------------------------------------------------------------------------------
		DateTime::DateTime(const DateTime &DateSrc) : 	m_Time(DateSrc.m_Time)
		{ 

		}


		//---------------------------------------------------------------------------------------
		// Function name	: DateTime()
		// Description	    : Constructs a Date object from individual components.
		// Return type		: Nothing
		// Argument         : int nYear
		//                    int nMonth
		//                    int nDay
		//                    int nHour
		//                    int nMin
		//                    int nSec
		//                    int nDST /*=-1*/
		//---------------------------------------------------------------------------------------
		DateTime::DateTime(int nYear, int nMonth, int nDay, int nHour, int nMin, int nSec, int nDST/*=-1*/)
		{
			tm atm = {0};
			atm.tm_sec = nSec;
			atm.tm_min = nMin;
			atm.tm_hour = nHour;
			assert(nDay >= 1 && nDay <= 31);
			atm.tm_mday = nDay;
			assert(nMonth >= 1 && nMonth <= 12);
			atm.tm_mon = nMonth - 1;        // tm_mon is 0 based
			assert(nYear >= 1900);
			atm.tm_year = nYear - 1900;     // tm_year is 1900 based
			atm.tm_isdst = nDST;
			m_Time = ::mktime(&atm);
			assert(m_Time != -1);       // indicates an illegal input time
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetSystemCurrentTime()
		// Description	    : This is a static method that returns the current system time.
		// Return type		: DateTime
		//						Date object representing current system time.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		/*static*/ DateTime DateTime::GetSystemCurrentTime()
		{
			return DateTime(::time(NULL));
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetGmtTm()
		// Description	    : Breaks down a Date object into components — based on UTC. Call NSS
		//                    for the dirty work, populates a C language tm structure and returns it.
		// Return type		: auto_ptr<tm>
		//						Smart pointer to tm structure.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		const tm *DateTime::GetGmtTm() const
		{
			return ::gmtime(&m_Time);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetLocalTm()
		// Description	    : Breaks down a Date object into components — based on the local time zone.
		//					  Calls NSS for the dirty work, populates a C langugae tm structure and returns
		//                    it to the caller.
		// Return type		: auto_ptr<tm>
		//						Smart pointer to tm structure.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		const tm *DateTime::GetLocalTm() const
		{
			return ::localtime(&m_Time);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator=()
		// Description	    : Copy assignment operator.
		// Return type		: DateTime &
		//						*this
		// Argument         : const DateTime &DateSrc
		//						reference to the Date object from which to assign.
		//---------------------------------------------------------------------------------------
		DateTime &DateTime::operator=(const DateTime &DateSrc)
		{ 
			// Check for self assignment
			if (this == &DateSrc) 
				return *this;

			m_Time = DateSrc.m_Time; 
			return *this; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator=()
		// Description	    : Assignment operator for assignment from a time_t.
		// Return type		: DateTime &
		//						*this
		// Argument         : time_t t
		//						time_t from which to assign.
		//---------------------------------------------------------------------------------------
		DateTime &DateTime::operator=(time_t t)
		{ 
			m_Time = t; 
			return *this; 
		}



		//---------------------------------------------------------------------------------------
		// Function name	: GetTime()
		// Description	    : Returns internal time_t.
		// Return type		: time_t
		//						Internal time_t.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		time_t  DateTime::GetTime() const
		{
			return m_Time; 
		}



		//---------------------------------------------------------------------------------------
		// Function name	: GetYear()
		// Description	    : Returns year of this Date object. Implemented in terms of member function
		//                    GetLocalTime().
		// Return type		: int
		//						integer representing year.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetYear() const
		{ 
			return (GetLocalTm()->tm_year) + 1900; // this 1900 can be faulty. Have to test it.
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetMonth()
		// Description	    : Returns month of this Date object. Implemented in terms of member function
		//                    GetLocalTime().
		// Return type		: int
		//						integer representing month.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetMonth() const
		{ 
			return GetLocalTm()->tm_mon + 1; 
		}



		//---------------------------------------------------------------------------------------
		// Function name	: GetDay()
		// Description	    : Returns day of this Date object. Implemented in terms of member function
		//                    GetLocalTime().
		// Return type		: int
		//						integer representing day.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetDay() const
		{ 
			const tm *ptm = GetLocalTm();
			if(ptm)
				return ptm->tm_mday; 
			else
				return -1;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetHour()
		// Description	    : Returns hour of this Date object. Implemented in terms of member function
		//                    GetLocalTime().
		// Return type		: int
		//						integer representing hour.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetHour() const
		{ 
			return GetLocalTm()->tm_hour; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetMinute()
		// Description	    : Returns minute of this Date object. Implemented in terms of member function
		//                    GetLocalTime().
		// Return type		: int
		//						integer representing minute.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetMinute() const
		{ 
			return GetLocalTm()->tm_min; 
		}



		//---------------------------------------------------------------------------------------
		// Function name	: GetSecond()
		// Description	    : Returns second of this Date object. Implemented in terms of member function
		//                    GetLocalTime().
		// Return type		: int
		//						integer representing second.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetSecond() const
		{ 
			return GetLocalTm()->tm_sec; 
		}



		//---------------------------------------------------------------------------------------
		// Function name	: GetDayOfWeek()
		// Description	    : Returns day of a week of this Date object. Implemented in terms of 
		//                    member function GetLocalTime().
		// Return type		: int
		//						integer representing day of week.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		int DateTime::GetDayOfWeek() const
		{ 
			return GetLocalTm()->tm_wday + 1; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator==()
		// Description	    : Equality operator. 
		// Return type		: bool
		//						returns true if this Date object is equal to rhs otherwise false.
		// Argument         : DateTime Date
		//						Date object to compare with.
		//---------------------------------------------------------------------------------------
		bool DateTime::operator==(DateTime Date) const
		{ 
			return m_Time == Date.m_Time; 
		}

		//---------------------------------------------------------------------------------------
		// Function name	: operator!=()
		// Description	    : Inequality operator.
		// Return type		: bool
		//						returns true if this Date object is not equal to rhs otherwise false.
		// Argument         : DateTime Date
		//						Date object to compare with.
		//---------------------------------------------------------------------------------------
		bool DateTime::operator!=(DateTime Date) const
		{ 
			return m_Time != Date.m_Time; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator<()
		// Description	    : Less than operator.
		// Return type		: bool
		//						returns true if this Date object is less than rhs otherwise false.
		// Argument         : DateTime Date
		//						Date object to compare with.
		//---------------------------------------------------------------------------------------
		bool DateTime::operator<(DateTime Date) const
		{ 
			return m_Time < Date.m_Time; 
		}

		//---------------------------------------------------------------------------------------
		// Function name	: operator>()
		// Description	    : Greater than operator.
		// Return type		: bool
		//						returns true if this Date object is greater than rhs otherwise false.
		// Argument         : DateTime Date
		//						Date object to compare with.
		//---------------------------------------------------------------------------------------
		bool DateTime::operator>(DateTime Date) const
		{ 
			return m_Time > Date.m_Time; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator<=()
		// Description	    : Less than or equal to operator.
		// Return type		: bool
		//						returns true if this Date object is less than or equal to rhs otherwise false.
		// Argument         : DateTime Date
		//						Date object to compare with.
		//---------------------------------------------------------------------------------------
		bool DateTime::operator<=(DateTime Date) const
		{ 
			return m_Time <= Date.m_Time; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator>=()
		// Description	    : Greater than or equal to operator.
		// Return type		: bool
		//						returns true if this Date object is greater than or equal to rhs otherwise false.
		// Argument         : DateTime Date
		//						Date object to compare with.
		//---------------------------------------------------------------------------------------
		bool DateTime::operator>=(DateTime Date) const
		{ 
			return m_Time >= Date.m_Time; 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: Format()
		// Description	    : Converts a Date object into a formatted string — based on the local time
		//                    zone. Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		std::string DateTime::Format(const char *pFormat) const
		{
			char szBuffer[maxTimeBufferSize] = {0};
			struct tm* ptmTemp = ::localtime(&m_Time);
			if(!ptmTemp)
				return "";

			::strftime(szBuffer, COUNTOF(szBuffer), pFormat, ptmTemp);
			return szBuffer;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FormatGmt()
		// Description	    : Converts a Date object into a formatted string — based on the UTC. 
		//                    Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		std::string DateTime::FormatGmt(const char *pFormat) const
		{
			char szBuffer[maxTimeBufferSize] = {0};
			struct tm* ptmTemp = ::gmtime(&m_Time);
			if(!ptmTemp)
				return "";

			::strftime(szBuffer, COUNTOF(szBuffer), pFormat, ptmTemp);
			return szBuffer;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FormatGmt()
		// Description	    : Converts a Date object into a formatted string — based on the UTC. 
		//                    Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		TimeSpan DateTime::operator-( DateTime Time ) const
		{
			return( TimeSpan( m_Time - Time.m_Time ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FormatGmt()
		// Description	    : Converts a Date object into a formatted string — based on the UTC. 
		//                    Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		DateTime DateTime::operator-( TimeSpan Span ) const
		{
			return( DateTime( m_Time - Span.GetTimeSpan() ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FormatGmt()
		// Description	    : Converts a Date object into a formatted string — based on the UTC. 
		//                    Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		DateTime DateTime::operator+( TimeSpan Span ) const
		{
			return( DateTime( m_Time + Span.GetTimeSpan() ) );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FormatGmt()
		// Description	    : Converts a Date object into a formatted string — based on the UTC. 
		//                    Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		DateTime &DateTime::operator+=( TimeSpan Span )
		{
			m_Time += Span.GetTimeSpan();

			return( *this );
		}


		//---------------------------------------------------------------------------------------
		// Function name	: FormatGmt()
		// Description	    : Converts a Date object into a formatted string — based on the UTC. 
		//                    Same semantics as strftime(). 
		// Return type		: string
		//						string representation of this Date object.
		// Argument         : const char *pFormat
		//						buffer containing format specifiers e.g. "%c"
		//---------------------------------------------------------------------------------------
		DateTime &DateTime::operator-=( TimeSpan Span )
		{
			m_Time -= Span.GetTimeSpan();

			return( *this );
		}
	}
}


