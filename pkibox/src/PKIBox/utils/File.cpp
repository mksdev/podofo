
#include <cassert>
#include <errno.h>
#include "File.h"
#include "../Exception.h"
#include "ByteArray.h"

#define _MAX_PATH	260 
#define _MAX_DRIVE	3 
#define _MAX_DIR	256 
#define _MAX_FNAME	256 
#define _MAX_EXT	256 

using namespace std;

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
		File::File()
		{

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		File::File(const string &strFilePath, ios_base::openmode Openmode) 
			: m_strFilePath(strFilePath), m_Openmode(Openmode), m_File(strFilePath.c_str(), Openmode)
		{
			if(!m_File)
				throw Exception("Bad path or file does not exist.");

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		/*virtual*/ File::~File()
		{
			m_File.close();
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		unsigned int File::GetLength() /* throw (Exception) */
		{
			long l = m_File.tellg();
			if(!m_File.good())
				throw Exception("Seek operation on file failed.");

			m_File.seekg(0, ios_base::end);
			if(!m_File.good())
				throw Exception("Seek operation on file failed.");

			long m = m_File.tellg();
			if(!m_File.good())
				throw Exception("Seek operation on file failed.");

			m_File.seekg(0, ios_base::beg);
			if(!m_File.good())
				throw Exception("Seek operation on file failed.");

			return (m - l);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void File::Read(char *pBuff, unsigned int nCount) /* throw (Exception) */
		{
			assert(pBuff != NULL);

			m_File.read(pBuff, nCount);

			if(!m_File.good())
				throw Exception("Reading from file failed.");

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void File::Write(const char *pBuff, unsigned int nCount) /* throw (Exception) */
		{
			assert(pBuff != NULL);

			m_File.write(pBuff, nCount);

			if(!m_File.good())
				throw Exception("Writing to file failed.");
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void File::Clear()
		{
			m_File.close();
			m_File.open(m_strFilePath.c_str(), m_Openmode | ios::trunc);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Loads the contents of the File into the ByteArray. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		/*static*/ ByteArray File::Load(const string& Filename) /* throw (Exception) */
		{
			File File(Filename, ios::in | ios::binary);
			unsigned int cBuffer = File.GetLength();
			char *pBuffer = new char[cBuffer];
			File.Read(pBuffer, cBuffer);
			ByteArray ba( (unsigned char *)pBuffer, cBuffer);
			if(pBuffer)
				delete []pBuffer;
			return ba;
		}



		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Saves the ByteArray into the File given by filename. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		/*static*/ void File::Save(const string &Filename, const ByteArray &Bytes) /* throw (Exception) */
		{
			File File(Filename, ios::out | ios::binary | ios_base::trunc);
			File.Write(reinterpret_cast<const char *>(Bytes.GetData()), Bytes.GetLength());
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Saves the ByteArray into the File given by filename. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		/*static*/ bool File::Remove(const string& Filename) /* throw (Exception) */
		{
			int rv = ::remove(Filename.c_str());
			if(rv == -1)
			{
				throw Exception(strerror(errno));
			}
			else 
				return true;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Saves the ByteArray into the File given by filename. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		/*static*/ bool File::Exists(const string& Filename) /* throw (Exception) */
		{
			ifstream is(Filename.c_str());
			if(!is)
				return false;

			is.close();
			return true;
		}

#ifdef WIN32
		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Saves the ByteArray into the File given by filename. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		string File::GetFileName() const 
		{
			char path_buffer[_MAX_PATH] = {0};
			char drive[_MAX_DRIVE] = {0}; 
			char dir[_MAX_DIR] = {0}; 
			char fname[_MAX_FNAME] = {0}; 
			char ext[_MAX_EXT] = {0}; 

			::_splitpath(m_strFilePath.c_str(), drive, dir, fname, ext);
			strcat(path_buffer, fname);
			return strcat(path_buffer, ext);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Saves the ByteArray into the File given by filename. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		string File::GetFileTitle() const
		{
			char drive[_MAX_DRIVE] = {0}; 
			char dir[_MAX_DIR] = {0}; 
			char fname[_MAX_FNAME] = {0}; 
			char ext[_MAX_EXT] = {0}; 

			::_splitpath(m_strFilePath.c_str(), drive, dir, fname, ext);
			return fname;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : /* Saves the ByteArray into the File given by filename. */
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		string File::GetFileDirectory() const
		{
			char path_buffer[_MAX_PATH] = {0};
			char drive[_MAX_DRIVE] = {0}; 
			char dir[_MAX_DIR] = {0}; 
			char fname[_MAX_FNAME] = {0}; 
			char ext[_MAX_EXT] = {0}; 

			::_splitpath(m_strFilePath.c_str(), drive, dir, fname, ext);

			strcat(path_buffer, drive);
			return strcat(path_buffer, dir);

		}
#endif
	}

}


